// Description: Implement specific services provided by AS

package akissuer

/*
#cgo CFLAGS: -I../../tee/tverlib/verifier
#cgo LDFLAGS: -L${SRCDIR}/../../tee/tverlib/verifier -lteeverifier -Wl,-rpath=${SRCDIR}/../../tee/tverlib/verifier
#include "teeverifier.h"
*/
import "C"
import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"log"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
)

const (
	ZERO_VALUE          = 0
	UINT32_BYTES_LENGTH = 4
	UINT64_BYTES_LENGTH = 8
	// tag type
	KEY_TAG_TYPE_MOVE_BITS = 28
	RA_INTEGER             = (1 << KEY_TAG_TYPE_MOVE_BITS)
	RA_BYTES               = (2 << KEY_TAG_TYPE_MOVE_BITS)
	RA_TAG_SIGN_TYPE       = RA_INTEGER
	RA_TAG_HASH_TYPE       = RA_INTEGER | 1
	RA_TAG_QTA_IMG_HASH    = RA_BYTES
	RA_TAG_TA_IMG_HASH     = RA_BYTES | 1
	RA_TAG_QTA_MEM_HASH    = RA_BYTES | 2
	RA_TAG_TA_MEM_HASH     = RA_BYTES | 3
	RA_TAG_RESERVED        = RA_BYTES | 4
	RA_TAG_AK_PUB          = RA_BYTES | 5
	RA_TAG_SIGN_DRK        = RA_BYTES | 6
	RA_TAG_SIGN_AK         = RA_BYTES | 7
	RA_TAG_CERT_DRK        = RA_BYTES | 8
	RA_TAG_CERT_AK         = RA_BYTES | 9
	// alg type
	RA_ALG_RSA_3072    = 0x20000
	RA_ALG_RSA_4096    = 0x20001 // PSS padding
	RA_ALG_SHA_256     = 0x20002
	RA_ALG_SHA_384     = 0x20003
	RA_ALG_SHA_512     = 0x20004
	RA_ALG_ECDSA       = 0x20005
	RA_ALG_ED25519     = 0x20006
	RA_ALG_SM2_DSA_SM3 = 0x20007
	RA_ALG_SM3         = 0x20008
)

type (
	ra_data_offset struct {
		data_len    uint32
		data_offset uint32
	}
	ra_params struct {
		tags uint32
		buf  interface{}
	}
	certificate struct {
		version     uint32
		timestamp   uint64
		tag         string
		param_count uint32
		params      []ra_params
	}
)

// The input parameter is the AK certificate issued by the target platform device certificate
// After receiving the AK certificate, parse and extract the signed data fields,
// signature fields, and DRK certificate fields
// Parse the DRK certificate
// Use huawei Level-2 certificate to check the DRK certificate.
// If the DRK certificate passes the check, the DRK certificate is trusted
// Use the DRK certificate to check the AK certificate.
// If the AK certificate passes the check, the AK certificate is trusted
// Re-sign the AK certificate using the AS private key
// Return the re-signed AK certificate
func GenerateAKCert(oldAKCert []byte) ([]byte, error) { // dvcert -> drkcert
	// STEP1: get data used for verify
	var c_cert, c_signdata, c_signdrk, c_certdrk, c_akpub C.buffer_data
	c_cert.size = C.uint(len(oldAKCert))
	up_old_cert := C.CBytes(oldAKCert)
	defer C.free(up_old_cert)
	c_cert.buf = (*C.uchar)(up_old_cert)
	C.getNOASdata(&c_cert, &c_signdata, &c_signdrk, &c_certdrk, &c_akpub)
	drkcertbyte := []byte(C.GoBytes(unsafe.Pointer(c_certdrk.buf), C.int(c_certdrk.size)))
	// STEP2: parse device cert
	drkcertBlock, _ := pem.Decode(drkcertbyte)
	drkcert, err := x509.ParseCertificate(drkcertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	log.Print("Server: Parse drk cert succeeded.")
	// STEP3: verify device cert signature
	err = verifyDRKSig(drkcert)
	if err != nil {
		return nil, errors.New("verify drk signature failed")
	}
	log.Print("Server: Verify drk signature ok.")
	// STEP4: verify ak cert signature
	rs := C.verifysig(&c_signdata, &c_signdrk, &c_certdrk, 1)
	if !bool(rs) {
		return nil, errors.New("verify ak signature failed")
	}
	log.Print("Server: Verify ak signature ok.")
	// STEP5: get as private key
	asprivkey := config.GetASPrivKey()
	// STEP6: resign ak cert
	newCertDer, err := signForAKCert(oldAKCert, asprivkey)
	if err != nil {
		return nil, err
	}
	log.Print("Server: resign ak cert ok.")
	newCertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCertDer,
	}
	newCertPem := pem.EncodeToMemory(newCertBlock)
	// d, err := database.InsertDKeyRow(drkcertbyte)
	// if err != nil {
	// 	log.Printf("Insert device key row failed, error: %v", err)
	// }
	// err = database.InsertAKCertRow(newCertPem, d.Id)
	// if err != nil {
	// 	log.Printf("Insert AKey Cert row failed, error: %v", err)
	// }
	return newCertPem, nil
}

func parseCustomCert(certByte []byte) (*certificate, error) {
	if certByte == nil {
		return nil, errors.New("empty cert")
	}
	var c *certificate = &certificate{}
	c.params = make([]ra_params, 0)
	var offset int = 4
	c.version = bytesToUint(certByte[:offset]).(uint32)
	c.timestamp = bytesToUint(certByte[offset : offset+8]).(uint64)
	offset += 8
	c.tag = string(certByte[offset : offset+32])
	offset += 32
	c.param_count = bytesToUint(certByte[offset : offset+4]).(uint32)
	offset += 4
	for i := 0; i < int(c.param_count); i++ {
		tags := bytesToUint(certByte[offset : offset+4]).(uint32)
		switch tags {
		case RA_TAG_SIGN_TYPE:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_SIGN_TYPE
			c.params[i].buf = bytesToUint(certByte[offset+4 : offset+12]).(uint64)
			offset += 12
		case RA_TAG_HASH_TYPE:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_HASH_TYPE
			c.params[i].buf = bytesToUint(certByte[offset+4 : offset+12]).(uint64)
			offset += 12
		case RA_TAG_QTA_IMG_HASH:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_QTA_IMG_HASH
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		case RA_TAG_QTA_MEM_HASH:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_QTA_MEM_HASH
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		case RA_TAG_RESERVED:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_RESERVED
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		case RA_TAG_AK_PUB:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_AK_PUB
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		case RA_TAG_SIGN_DRK:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_SIGN_DRK
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		case RA_TAG_CERT_DRK:
			c.params = append(c.params, ra_params{})
			c.params[i].tags = RA_TAG_CERT_DRK
			c.params[i].buf = ra_data_offset{
				data_len:    bytesToUint(certByte[offset+4 : offset+8]).(uint32),
				data_offset: bytesToUint(certByte[offset+8 : offset+12]).(uint32),
			}
			offset += 12
		}
	}
	return c, nil
}

func bytesToUint(b []byte) interface{} {
	bytesBuffer := bytes.NewBuffer(b)
	length := len(b)
	switch length {
	case UINT32_BYTES_LENGTH:
		var x uint32
		binary.Read(bytesBuffer, binary.LittleEndian, &x)
		return x
	case UINT64_BYTES_LENGTH:
		var x uint64
		binary.Read(bytesBuffer, binary.LittleEndian, &x)
		return x
	}
	return nil
}

func verifyDRKSig(c *x509.Certificate) error {
	hwcert := config.GetHWCert()
	err := c.CheckSignatureFrom(hwcert)
	if err != nil {
		return err
	}
	return nil
}

func signForAKCert(cb []byte, priv interface{}) ([]byte, error) {
	// parse ak cert signed by device cert
	c, err := parseCustomCert(cb)
	if err != nil {
		return nil, err
	}
	// get data need to be hashed end point and sign data length
	endPoint, sdlen := getHashScopeAndSignLen(c)
	if endPoint == ZERO_VALUE {
		return nil, errors.New("drk signature not found")
	}
	// extract hash algorithm
	alg_hash := extractHashAlg(c)
	if alg_hash == ZERO_VALUE {
		return nil, errors.New("hash type not found")
	}
	// extract sign algorithm
	alg_sign := extractSignAlg(c)
	if alg_sign == ZERO_VALUE {
		return nil, errors.New("sign type not found")
	}
	// calculate hash value
	var hbytes []byte
	switch alg_hash {
	case RA_ALG_SHA_256:
		h := sha256.New()
		h.Write(cb[:endPoint])
		hbytes = h.Sum(nil)
	default:
		return nil, errors.New("hash algorithm not support yet")
	}
	// sign the hash value
	var signdata []byte
	switch alg_sign {
	case RA_ALG_RSA_4096:
		signdata, err = rsa.SignPSS(rand.Reader, priv.(*rsa.PrivateKey), crypto.SHA256, hbytes, nil)
		if err != nil {
			return nil, errors.New("signature error")
		}
	default:
		return nil, errors.New("signature algorithm not support yet")
	}
	// generate new bytes
	for i := 0; i < sdlen; i++ {
		cb[int(endPoint)+i] = signdata[i]
	}

	return cb, nil
}

func getHashScopeAndSignLen(c *certificate) (uint32, int) {
	for i := 0; i < int(c.param_count); i++ {
		if c.params[i].tags == RA_TAG_SIGN_DRK {
			endPoint := c.params[i].buf.(ra_data_offset).data_offset
			sdlen := int(c.params[i].buf.(ra_data_offset).data_len)
			return endPoint, sdlen
		}
	}
	return 0, 0
}

func extractHashAlg(c *certificate) uint64 {
	for i := 0; i < int(c.param_count); i++ {
		if c.params[i].tags == RA_TAG_HASH_TYPE {
			alg_hash := c.params[i].buf.(uint64)
			return alg_hash
		}
	}
	return 0
}

func extractSignAlg(c *certificate) uint64 {
	for i := 0; i < int(c.param_count); i++ {
		if c.params[i].tags == RA_TAG_SIGN_TYPE {
			alg_sign := c.params[i].buf.(uint64)
			return alg_sign
		}
	}
	return 0
}
