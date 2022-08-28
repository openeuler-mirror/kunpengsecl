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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"sync"
	"time"
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
	// x509 cert template default value
	strChina      = "China"
	strCompany    = "Company"
	strCommonName = "AK Server"
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

var (
	m            sync.Mutex
	serialNumber int64 = 1
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
func GenerateAKCert(oldAKCert []byte) ([]byte, error) {
	// STEP1: get data used for verify
	var c_cert, c_signdata, c_signdrk, c_certdrk, c_akpub C.buffer_data
	c_cert.size = C.uint(len(oldAKCert))
	up_old_cert := C.CBytes(oldAKCert)
	defer C.free(up_old_cert)
	c_cert.buf = (*C.uchar)(up_old_cert)
	C.getDataFromAkCert(&c_cert, &c_signdata, &c_signdrk, &c_certdrk, &c_akpub)
	drkcertbyte := []byte(C.GoBytes(unsafe.Pointer(c_certdrk.buf), C.int(c_certdrk.size)))
	// STEP2: get data used for re-sign
	signdrkbyte := []byte(C.GoBytes(unsafe.Pointer(c_signdrk.buf), C.int(c_signdrk.size)))
	akpubbyte := []byte(C.GoBytes(unsafe.Pointer(c_akpub.buf), C.int(c_akpub.size)))
	b := big.NewInt(0)
	b.SetBytes(akpubbyte)
	akpub := &rsa.PublicKey{
		N: b,
		E: 0x10001,
	}
	// STEP3: parse device cert
	drkcertBlock, _ := pem.Decode(drkcertbyte)
	drkcert, err := x509.ParseCertificate(drkcertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	log.Print("Server: Parse drk cert succeeded.")
	// STEP4: verify device cert signature
	err = verifyDRKSig(drkcert)
	if err != nil {
		return nil, errors.New("verify drk signature failed")
	}
	log.Print("Server: Verify drk signature ok.")
	// STEP5: verify ak cert signature
	rs := C.verifysig(&c_signdata, &c_signdrk, &c_certdrk, 1)
	if !bool(rs) {
		return nil, errors.New("verify ak signature failed")
	}
	log.Print("Server: Verify ak signature ok.")
	// STEP6: get as private key and as cert
	asprivkey := config.GetASPrivKey()
	ascert := config.GetASCert()
	// STEP7: re-sign ak cert
	newCertDer, err := signForAKCert(oldAKCert, ascert, signdrkbyte, akpub, asprivkey)
	if err != nil {
		return nil, err
	}
	log.Print("Server: re-sign ak cert ok.")
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

// AS will uses its private key/cert to re-sign AK cert,
// and convert AK cert to x509 format
// TODO: Measure value in AK cert should be verified before sending to AS
func signForAKCert(cb []byte, parent *x509.Certificate, sign []byte, pub interface{}, priv interface{}) ([]byte, error) {
	var ACtemplate = x509.Certificate{
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
	}
	var akcertDer []byte
	// parse ak cert signed by device cert
	c, err := parseCustomCert(cb)
	if err != nil {
		return nil, err
	}
	// set AK Cert id, version and signature field
	m.Lock()
	id := serialNumber
	serialNumber++
	m.Unlock()
	ACtemplate.SerialNumber = big.NewInt(id)
	ACtemplate.Signature = append(ACtemplate.Signature, sign...)
	// extract sign algorithm
	alg_sign := extractSignAlg(c)
	if alg_sign == ZERO_VALUE {
		return nil, errors.New("sign type not found")
	}
	switch alg_sign {
	case RA_ALG_RSA_4096:
		ACtemplate.PublicKeyAlgorithm = x509.RSA
	default:
		return nil, errors.New("signature algorithm not support yet")
	}
	// extract hash algorithm
	alg_hash := extractHashAlg(c)
	if alg_hash == ZERO_VALUE {
		return nil, errors.New("hash type not found")
	}
	switch alg_hash {
	case RA_ALG_SHA_256:
		ACtemplate.SignatureAlgorithm = x509.SHA256WithRSAPSS
	default:
		return nil, errors.New("hash algorithm not support yet")
	}

	akcertDer, err = x509.CreateCertificate(rand.Reader, &ACtemplate, parent, pub, priv)
	if err != nil {
		return nil, err
	}

	return akcertDer, nil
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
