// kcmstools package implements the whole process of key caching management service
package kcmstools

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
	uuid "github.com/satori/go.uuid"
)

var deviceId int64 = 1238263726351263121

func SendKCMPubKeyCert() ([]byte, error) {
	// TODO: get KCM public key cert
	kcm_cert, err := ReadCert("../cert/kcm.crt")
	if err != nil {
		return nil, err
	}
	// TODO: return KCM publick key cert, error
	return kcm_cert, nil
}

func VerifyKTAPubKeyCert(deviceId int64, ktaPubKeyCert string) error {
	// unmarshal cert to *x509.Certificate
	_, _, err := cryptotools.DecodeKeyCertFromPEM([]byte(ktaPubKeyCert))
	if err != nil {
		return err
	}

	// temporarily save ktaPubKeyCert in cert folder
	err = SaveCert([]byte(ktaPubKeyCert), "../cert/", "kta.crt")
	if err != nil {
		return err
	}

	// verify KTA cert
	_, err = VerifyPubCert("../cert/ca.crt", "../cert/kta.crt")
	if err != nil {
		return err
	}

	// TODO: save kta public key cert to database
	base64_pubkeyCert := base64.StdEncoding.EncodeToString([]byte(ktaPubKeyCert))
	_, err = kdb.SavePubKeyInfo(deviceId, base64_pubkeyCert)
	if err != nil {
		return err
	}
	return nil
}

func GenerateNewKey(taid []byte, account []byte, password []byte, hostkeyid []byte) ([]byte, []byte, []byte, []byte, error) {
	// TODO: get the trusted status of TA (from cache)(trustmgr.GetCache)

	// ask KMS to generate a new key for the specific TA,
	// getting (plaintext, ciphertext)
	str_taid := string(taid)
	_, ciphertext, plaintext, err := KmsGenerateKey(account, password, hostkeyid)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// generate a random keyid
	keyid := uuid.NewV4().String()

	// save information(taid, keyid, ciphertext) of the
	// new key to database
	_, err = kdb.SaveKeyInfo(str_taid, keyid, string(ciphertext))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// generate a session key K (symmetric, and can only
	// be decryped by KTA)
	K := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, nil, nil, err
	}

	// use K to encrypt plaintext
	enc_plaintext, err := EncryptWithAES256GCM(plaintext, K)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// use kta public key to encrypt K (can only be decryped by KTA))
	pubkey, err := kdb.FindPubKeyInfo(deviceId)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	KtaPublickeyCert, err := base64.StdEncoding.DecodeString(pubkey.PubKeyCert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pubkeycert, _, err := cryptotools.DecodeKeyCertFromPEM(KtaPublickeyCert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	label := []byte("label")
	enc_k, err := cryptotools.AsymmetricEncrypt(0x0001, 0x0000, pubkeycert.PublicKey, K, label)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// return taid, ENC(K), ENC(plaintext), keyId, error
	return taid, enc_k, enc_plaintext, []byte(keyid), nil
}

func GetKey(taid []byte, account []byte, password []byte, keyid []byte, hostkeyid []byte) ([]byte, []byte, []byte, []byte, error) {
	// TODO: get the trusted status of TA (from cache)

	// find ciphertext of the specific key
	// in database by (taid, keyid)
	str_taid := string(taid)
	str_keyid := string(keyid)
	findkey, err := kdb.FindKeyInfo(str_taid, str_keyid)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// ask KMS to decrypt ciphertext, getting plaintext
	_, _, plaintext, err := KmsGetKey(account, password, findkey.Ciphertext, hostkeyid)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// generate a session key K
	// (symmetric, and can only be decryped by KTA)
	K := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, K); err != nil {
		return nil, nil, nil, nil, err
	}
	fmt.Printf("K: %v \n", K)

	// use K to encrypt plaintext
	enc_plaintext, err := EncryptWithAES256GCM(plaintext, K)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// use kta public key to encrypt K
	// (can only be decryped by KTA))
	pubkey, err := kdb.FindPubKeyInfo(deviceId)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	KtaPublickeyCert, err := base64.StdEncoding.DecodeString(pubkey.PubKeyCert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pubkeycert, _, err := cryptotools.DecodeKeyCertFromPEM(KtaPublickeyCert)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	label := []byte("label")
	enc_k, err := cryptotools.AsymmetricEncrypt(0x0001, 0x0000, pubkeycert.PublicKey, K, label)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// return taid, ENC(K), ENC(plaintext),keyid,  error
	return taid, enc_k, enc_plaintext, keyid, nil
}

func DeleteKey(taid []byte, keyid []byte) error {
	// TODO: get the trusted status of TA (from cache)

	str_taid := string(taid)
	str_keyid := string(keyid)
	// delete the specific key in database
	err2 := kdb.DeleteKeyInfo(str_taid, str_keyid)
	if err2 != nil {
		return err2
	}
	return nil
}

func KmsGenerateKey(account, passwd, hostkeyid []byte) ([]byte, []byte, []byte, error) {
	_ = account
	_ = passwd
	_ = hostkeyid
	return nil, []byte("ciphertext"), []byte("plaintext"), nil
}

func KmsGetKey(account []byte, passwd []byte, ciphertext string, hostkeyid []byte) ([]byte, []byte, []byte, error) {
	_ = account
	_ = passwd
	_ = hostkeyid
	_ = ciphertext
	return nil, nil, []byte("plaintext"), nil
}

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
