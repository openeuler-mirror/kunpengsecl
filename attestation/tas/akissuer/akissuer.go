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
	"miracl/core"
	"miracl/core/FP256BN"
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
	RA_TAG_CURVE_TYPE      = RA_INTEGER | 2
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
	RA_ALG_RSA_3072        = 0x20000
	RA_ALG_RSA_4096        = 0x20001 // PSS padding
	RA_ALG_SHA_256         = 0x20002
	RA_ALG_SHA_384         = 0x20003
	RA_ALG_SHA_512         = 0x20004
	RA_ALG_ECDSA           = 0x20005
	RA_ALG_ED25519         = 0x20006
	RA_ALG_SM2_DSA_SM3     = 0x20007
	RA_ALG_SM3             = 0x20008
	RA_ALG_DAA_GRP_FP256BN = 0x20009
	// x509 cert template default value
	strChina                = "China"
	strCompany              = "Company"
	strCommonName           = "AK Server"
	RA_SCENARIO_NO_AS       = 0
	RA_SCENARIO_AS_NO_DAA   = 1
	RA_SCENARIO_AS_WITH_DAA = 2
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
func GenerateNoDAAAKCert(oldAKCert []byte) ([]byte, error) {
	// STEP1: get data used for verify
	var c_cert, c_signdata, c_signdrk, c_certdrk, c_akpub C.buffer_data
	c_cert.size = C.uint(len(oldAKCert))
	up_old_cert := C.CBytes(oldAKCert)
	defer C.free(up_old_cert)
	c_cert.buf = (*C.uchar)(up_old_cert)
	C.getDataFromAkCert(&c_cert, &c_signdata, &c_signdrk, &c_certdrk, &c_akpub, nil)
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

func GenerateDAAAKCert(oldAKCert []byte) ([]byte, error) {
	// STEP1: get data used for verify
	var c_cert, c_signdata, c_signdrk, c_certdrk, c_akprip1 C.buffer_data
	c_cert.size = C.uint(len(oldAKCert))
	up_old_cert := C.CBytes(oldAKCert)
	defer C.free(up_old_cert)
	c_cert.buf = (*C.uchar)(up_old_cert)
	C.getDataFromAkCert(&c_cert, &c_signdata, &c_signdrk, &c_certdrk, nil, &c_akprip1)
	drkcertbyte := []byte(C.GoBytes(unsafe.Pointer(c_certdrk.buf), C.int(c_certdrk.size)))
	// STEP2: get data used for re-sign 要看后面签名需要用到什么东西，在这里获取
	akprip1byte := []byte(C.GoBytes(unsafe.Pointer(c_akprip1.buf), C.int(c_akprip1.size)))
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

	//TODO: verify QCA & TCB

	skxstr, skystr := config.GetDAAGrpPrivKey()
	//TODO: generate cert[A, B, C, D]
	sig, err := MakeDAACredential(akprip1byte, skxstr, skystr)
	if err != nil {
		return nil, errors.New("make daa credential failed")
	}

	return sig, nil

}

func str2chunk(str string) *FP256BN.BIG {
	s := []byte(str) //len(s) = 64
	res := FP256BN.NewBIG()
	for i := 0; i < FP256BN.NLEN; i++ {
		var tmp []byte
		h := 0
		if len(s)-(i+1)*14 < 0 {
			for j := 0; j < 8; j++ {
				tmp[j] = s[j]
				h++
			}
			res.w[i] = FP256BN.FromBytes(tmp) //8
			return res
		}
		for j := len(s) - (i+1)*14; h < 14; j++ {
			tmp[h] = s[j]
			h++
		}
		res.w[i] = FP256BN.FromBytes(tmp) //14

	}
	return res
}

//var CURVE_Order = [...]Chunk{0x2D536CD10B500D, 0x65FB1299921AF6, 0x5EEE71A49E0CDC, 0xFFFCF0CD46E5F2, 0xFFFFFFFF}
//var sk_x = [...]FP256BN.Chunk{0xE97881A776543C, 0x6BE244F6E19274, 0xD2C6DEF16D48A5, 0xAC8832379FF04D, 0x65A9BF91}
//                                      14              14                 14               14              8
//var sk_y = [...]FP256BN.Chunk{0xD17E38F1773B56, 0xEC1EF24F81D189, 0x2C51825F980549, 0x8BB0CECA2AE752, 0x126F7425}
//x = "65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274 E97881A776543C"
func MakeDAACredential(akprip1 []byte, skxstr string, skystr string) ([]byte, error) {
	// random r l
	r := FP256BN.Random(core.NewRAND())
	l := FP256BN.Random(core.NewRAND())
	// daa private key
	skx := str2chunk(skxstr)
	sky := str2chunk(skystr)
	// TODO: check if public key is on the curve

	// A=[r]P_1
	P1 := FP256BN.ECP_generator()
	A := P1.Mul(r)
	// B=[y]A
	B := A.Mul(sky)
	// D=[ry]Q_s
	n := FP256BN.NewBIGints(FP256BN.CURVE_Order)
	ry := FP256BN.Modmul(r, sky, n) //n = bnp256_order
	var Qs FP256BN.ECP
	//获取Qs，将akprip1从byte[]转化成FP256BN.ECP
	D := Qs.Mul(ry)
	// tmp=A+D
	A.Add(D)
	tmp := A
	// C=[x]tmp
	C := tmp.Mul(skx)
	// R_B=[l]P1
	R_B := P1.Mul(l)
	// R_D=[l]Qs
	R_D := Qs.Mul(l)
	// u=sha256(P1,Qs,AKCert,R_B,R_D) 拼起来
	// u := sha256
	// j=l+yru, sigma=(u,j)
	yru := FP256BN.Modmul(ry, u, n)
	yru.Add(l)
	j := yru

	//TODO: choose a K to encrypt cert -> SECRET(cert)

	//TODO: use DRK to encrypt K -> SECRET(K)

	//return SECRET(K), SECRET(cert)
	return nil, nil
}

func GenerateAKCert(oldAKCert []byte, scenario int32) ([]byte, error) {
	switch scenario {
	case RA_SCENARIO_AS_NO_DAA:
		newCert, err := GenerateNoDAAAKCert(oldAKCert)
		if err != nil {
			log.Print("NoDAA scenario: Generate AK Cert failed!")
			return nil, err
		}
		log.Print("NoDAA scenario: Generate AK Cert succeeded!")
		return newCert, nil
	case RA_SCENARIO_AS_WITH_DAA:
		newCert, err := GenerateDAAAKCert(oldAKCert)
		if err != nil {
			log.Print("DAA scenario: Generate AK Cert failed!")
			return nil, err
		}
		log.Print("DAA scenario: Generate AK Cert succeeded!")
		return newCert, nil
	}
	return nil, errors.New("do not need to access as")
}
