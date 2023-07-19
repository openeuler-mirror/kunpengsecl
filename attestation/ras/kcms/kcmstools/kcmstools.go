/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

// kcmstools package implements the whole process of key caching management service
package kcmstools

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"github.com/gemalto/kmip-go"
	"github.com/gemalto/kmip-go/kmip14"
	"github.com/gemalto/kmip-go/ttlv"
	uuid "github.com/satori/go.uuid"
)

var (
	certPath     = "../cert/"
	ktaCertName  = "kta.crt"
	rootCertName = "ca.crt"
)

const (
	// AesKeySize means aes algorithm key size
	AesKeySize = 16
	// KeyIdSize means the size of key id
	KeyIdSize = 8
	// AlgAES means aes algorithm
	AlgAES = 0x0006
	// AlgCBC means cbc algorithm
	AlgCBC = 0x0042
)

func dailKMS() net.Conn {
	conn, err := net.DialTimeout("tcp", "localhost:5696", 3*time.Second)
	if err != nil {
		panic(err)
	}
	return conn
}

// SendKCMPubKeyCert sends kcm public key cert to ka.
func SendKCMPubKeyCert() ([]byte, error) {
	kcm_cert, err := ReadCert("../cert/kcm.crt")
	if err != nil {
		return nil, err
	}
	return kcm_cert, nil
}

// VerifyKTAPubKeyCert verifies weather kta public key cert
// which is signed by ca cert.
func VerifyKTAPubKeyCert(deviceId int64, ktaPubKeyCert []byte) error {
	// unmarshal cert to *x509.Certificate
	_, _, err := cryptotools.DecodeKeyCertFromPEM(ktaPubKeyCert)
	if err != nil {
		return err
	}

	// temporarily save ktaPubKeyCert in cert folder
	deviceStr := strconv.FormatInt(deviceId, 10)
	err = SaveCert([]byte(ktaPubKeyCert), certPath, deviceStr+ktaCertName)
	if err != nil {
		return err
	}

	// verify KTA cert
	_, err = VerifyPubCert(certPath+rootCertName, certPath+deviceStr+ktaCertName)
	if err != nil {
		return err
	}

	base64_pubkeyCert := base64.StdEncoding.EncodeToString([]byte(ktaPubKeyCert))
	_, err = kdb.SavePubKeyInfo(deviceId, base64_pubkeyCert)
	if err != nil {
		return err
	}

	// remove KTA cert
	err = os.Remove(certPath + deviceStr + ktaCertName)
	if err != nil {
		return errors.New("remove KTA cert error")
	}
	return nil
}

// GenerateNewKey firstly asks KMS to generate a new key for the specific TA
// according to host key id, then generates a random key id to save key
// ciphertext in the database, and returns plaintext of key, key id and session key
// which is generated randomly by kcms.
func GenerateNewKey(
	taid []byte,
	account []byte,
	password []byte,
	hostkeyid []byte,
	ktaid string,
	deviceId int64) ([]byte, []byte, []byte, []byte, []byte, error) {
	err := GetKTATrusted(deviceId, ktaid)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// ask KMS to generate a new key for the specific TA, getting (plaintext, ciphertext)
	str_taid := string(taid)
	_, ciphertext, plaintext, err := KmsGenerateKey(account, password, hostkeyid)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// generate a random keyid
	keyid := uuid.NewV4().String()

	// save information(taid, keyid, ciphertext) of the
	// new key to database
	b64_cipher := base64.StdEncoding.EncodeToString(ciphertext)
	_, err = kdb.SaveKeyInfo(str_taid, keyid, b64_cipher)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// generate a session key K (symmetric, and can only
	// be decryped by KTA)
	K := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// use kta public key to encrypt K (can only be decryped by KTA))
	pubkey, err := kdb.FindPubKeyInfo(deviceId)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	KtaPublickeyCert, err := base64.StdEncoding.DecodeString(pubkey.PubKeyCert)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return taid, K, KtaPublickeyCert, plaintext, []byte(keyid), nil
}

// GetKey firstly queries the database according to the key id
// to get the key ciphertext, then asks KMS to decrypt the ciphertext
// of key according to host key id, and returns plaintext of key, key id and session key
// which is generated randomly by kcms.
func GetKey(
	taid []byte,
	account []byte,
	password []byte,
	keyid []byte,
	hostkeyid []byte,
	ktaid string,
	deviceId int64) ([]byte, []byte, []byte, []byte, []byte, error) {
	err := GetKTATrusted(deviceId, ktaid)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	// find ciphertext of the specific key in database by (taid, keyid)
	str_taid := string(taid)
	str_keyid := string(keyid)
	findkey, err := kdb.FindKeyInfo(str_taid, str_keyid)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// ask KMS to decrypt ciphertext, getting plaintext
	_, _, plaintext, err := KmsGetKey(account, password, findkey.Ciphertext, hostkeyid)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// generate a session key K (symmetric, and can only be decryped by KTA)
	K := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	fmt.Printf("K: %v \n", K)

	// use K to encrypt plaintext
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// use kta public key to encrypt K
	// (can only be decryped by KTA))
	pubkey, err := kdb.FindPubKeyInfo(deviceId)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	KtaPublickeyCert, err := base64.StdEncoding.DecodeString(pubkey.PubKeyCert)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return taid, K, KtaPublickeyCert, plaintext, keyid, nil
}

// DeleteKey deletes the key ciphertext which is stored in kcms.
func DeleteKey(taid []byte, keyid []byte, ktaid string, deviceId int64) ([]byte, []byte, error) {
	err := GetKTATrusted(deviceId, ktaid)
	if err != nil {
		return nil, nil, err
	}

	str_taid := string(taid)
	str_keyid := string(keyid)

	// delete the specific key in database
	err = kdb.DeleteKeyInfo(str_taid, str_keyid)
	if err != nil {
		return nil, nil, err
	}

	// generate a session key K
	// (symmetric, and can only be decryped by KTA)
	K := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, err
	}
	fmt.Printf("K: %v \n", K)

	// use kta public key to encrypt K
	// (can only be decryped by KTA))
	pubkey, err := kdb.FindPubKeyInfo(deviceId)
	if err != nil {
		return nil, nil, err
	}
	KtaPublickeyCert, err := base64.StdEncoding.DecodeString(pubkey.PubKeyCert)
	if err != nil {
		return nil, nil, err
	}

	return K, KtaPublickeyCert, nil

}

// KmsGenerateKey creates a new key based on master key(host key),
// and returns key ciphertext and key plaintext.
func KmsGenerateKey(account, passwd, hostkeyid []byte) ([]byte, []byte, []byte, error) {
	conn := dailKMS()
	payload := kmip.CreateRequestPayload{
		ObjectType: kmip14.ObjectTypeSymmetricKey,
	}
	payload.TemplateAttribute.Append(kmip14.TagCryptographicAlgorithm, kmip14.CryptographicAlgorithmAES)
	payload.TemplateAttribute.Append(kmip14.TagCryptographicLength, 128)
	payload.TemplateAttribute.Append(
		kmip14.TagCryptographicUsageMask,
		kmip14.CryptographicUsageMaskEncrypt|kmip14.CryptographicUsageMaskDecrypt)
	payload.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, string(hostkeyid))
	payload.TemplateAttribute.Append(kmip14.TagDeviceIdentifier, account)
	payload.TemplateAttribute.Append(kmip14.TagPassword, passwd)
	biID := uuid.NewV4().Bytes()
	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 4,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				UniqueBatchItemID: biID[:],
				Operation:         kmip14.OperationCreate,
				RequestPayload:    &payload,
			},
		},
	}

	req, err := ttlv.Marshal(msg)
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = conn.Write(req)
	if err != nil {
		return nil, nil, nil, err
	}
	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	resp, err := decoder.NextTTLV()
	if err != nil {
		return nil, nil, nil, err
	}
	var respMsg kmip.ResponseMessage
	err = decoder.DecodeValue(&respMsg, resp)
	if err != nil {
		return nil, nil, nil, err
	}
	bi := respMsg.BatchItem[0]
	var respPayload kmip.CreateResponsePayload
	err = decoder.DecodeValue(&respPayload, bi.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, nil, nil, err
	}
	attr0 := respPayload.TemplateAttribute.Get(kmip14.TagUniqueIdentifier.String())
	mid := []byte(attr0.AttributeValue.(string))
	attr1 := respPayload.TemplateAttribute.Get(kmip14.TagSymmetricKey.CanonicalName())
	rawKey := attr1.AttributeValue.([]byte)
	attr2 := respPayload.TemplateAttribute.Get(kmip14.TagEncryptionKeyInformation.CanonicalName())
	cipherKey := attr2.AttributeValue.([]byte)
	return mid, cipherKey, rawKey, nil
}

// KmsGetKey decrypts key ciphertext based on master key(host key),
// and returns key ciphertext and key plaintext.
func KmsGetKey(account []byte, passwd []byte, ciphertext string, hostkeyid []byte) ([]byte, []byte, []byte, error) {
	conn := dailKMS()
	cipherByte, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}
	payload := typdefs.GetRequestPayload{}
	payload.TemplateAttribute = &kmip.TemplateAttribute{}
	payload.TemplateAttribute.Append(kmip14.TagUniqueIdentifier, string(hostkeyid))
	payload.TemplateAttribute.Append(kmip14.TagDeviceIdentifier, account)
	payload.TemplateAttribute.Append(kmip14.TagPassword, passwd)
	payload.TemplateAttribute.Append(kmip14.TagEncryptionKeyInformation, cipherByte)
	biID := uuid.NewV4().Bytes()
	msg := kmip.RequestMessage{
		RequestHeader: kmip.RequestHeader{
			ProtocolVersion: kmip.ProtocolVersion{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 4,
			},
			BatchCount: 1,
		},
		BatchItem: []kmip.RequestBatchItem{
			{
				UniqueBatchItemID: biID[:],
				Operation:         kmip14.OperationGet,
				RequestPayload:    &payload,
			},
		},
	}

	req, err := ttlv.Marshal(msg)
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = conn.Write(req)
	if err != nil {
		return nil, nil, nil, err
	}
	decoder := ttlv.NewDecoder(bufio.NewReader(conn))
	resp, err := decoder.NextTTLV()
	if err != nil {
		return nil, nil, nil, err
	}
	var respMsg kmip.ResponseMessage
	err = decoder.DecodeValue(&respMsg, resp)
	if err != nil {
		return nil, nil, nil, err
	}
	bi := respMsg.BatchItem[0]
	var respPayload typdefs.GetResponsePayload
	err = decoder.DecodeValue(&respPayload, bi.ResponsePayload.(ttlv.TTLV))
	if err != nil {
		return nil, nil, nil, err
	}
	attr0 := respPayload.TemplateAttribute.Get(kmip14.TagUniqueIdentifier.CanonicalName())
	mid := []byte(attr0.AttributeValue.(string))
	attr1 := respPayload.TemplateAttribute.Get(kmip14.TagSymmetricKey.CanonicalName())
	rawKey := attr1.AttributeValue.([]byte)
	attr2 := respPayload.TemplateAttribute.Get(kmip14.TagEncryptionKeyInformation.CanonicalName())
	cipherKey := attr2.AttributeValue.([]byte)
	return mid, cipherKey, rawKey, nil
}

// EncryptWithAES256GCM encrypts plaintext with the session key,
// and returns the ciphertext of the key.
func EncryptWithAES256GCM(plaintext []byte, sessionkey []byte) ([]byte, error) {
	c, err := aes.NewCipher(sessionkey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	fmt.Printf("nonce: %v \n", nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// VerifyPubCert verifies kta public key cert
// and returns ok if validation passes,
// otherwise returns an error message or null character.
func VerifyPubCert(cacertpath string, pubcertpath string) (string, error) {
	cmd := exec.Command("openssl", "verify", "-CAfile", cacertpath, pubcertpath)
	verify, err := cmd.Output()
	lenth := len(pubcertpath)
	result := string(verify[lenth+2 : lenth+4])
	if err == nil {
		fmt.Println(string(verify))
		if result == "OK" {
			return result, nil
		} else {
			return result, fmt.Errorf("check the command parameters")
		}
	} else {
		fmt.Println(err)
		return "", err
	}
}

// PathExists checks if the path exists,
// returns true if exists, otherwise return false.
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// SaveCert saves the certificate contents to the specified path.
func SaveCert(param []byte, certpath string, filename string) error {
	exist, err := PathExists(certpath)
	if err != nil {
		return err
	}
	if !exist {
		err = os.Mkdir(certpath, 0755)
		if err != nil {
			return err
		}
	}
	err = ioutil.WriteFile(certpath+filename, []byte(param), 0666)
	if err != nil {
		return err
	} else {
		return nil
	}
}

// ReadCert reads the certificate contents from the specified file pathname.
func ReadCert(pathname string) ([]byte, error) {
	file, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat() // get file propertity
	if err != nil {
		return nil, err
	}

	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)

	_, err = file.Read(buffer) // read file
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

// GetKTATrusted gets the trusted status of the KTA
// and verifies weather it is trusted.
func GetKTATrusted(deviceId int64, ktaid string) error {
	c, err := trustmgr.GetCache(deviceId)
	if err != nil {
		return err
	}
	if c.GetTaTrusted(ktaid) != cache.StrTrusted {
		fmt.Printf("\n c.GetTaTrusted(%s) = %s\n", ktaid, c.GetTaTrusted(ktaid))
		return errors.New("verify the KTA trusted status failed")
	}
	return nil
}
