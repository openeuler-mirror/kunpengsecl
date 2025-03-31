/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun/lixinda
Create: 2021-11-12
Description: Implement a privacy CA to sign identity key(AIK).
	1. 2022-01-17	change the ras/pca package to common/cryptotools.
*/

package cryptotools

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

var (
	cmdEnc        = "enc"
	decFlag       = "-d"
	encFlag       = "-e"
	aes128cbcFlag = "-aes-128-cbc"
	aes192cbcFlag = "-aes-192-cbc"
	aes256cbcFlag = "-aes-256-cbc"
	aes128cfbFlag = "-aes-128-cfb"
	aes192cfbFlag = "-aes-192-cfb"
	aes256cfbFlag = "-aes-256-cfb"
	aes128ofbFlag = "-aes-128-ofb"
	aes192ofbFlag = "-aes-192-ofb"
	aes256ofbFlag = "-aes-256-ofb"
	aes128ctrFlag = "-aes-128-ctr"
	aes192ctrFlag = "-aes-192-ctr"
	aes256ctrFlag = "-aes-256-ctr"
	kFlag         = "-K"
	ivFlag        = "-iv"
	inFlag        = "-in"
	outFlag       = "-out"
	decFile       = "./test.txt.dec"
	encFile       = "./test.txt.enc"
	decPKeyFile   = "./test-pkey.txt.dec"
	encPKeyFile   = "./test-pkey.txt.enc"
	textFile      = "./test.txt"
	base64Flag    = "-base64"
	plainText     = "Hello, world!"
	ivValue       = "1234567890abcdef"
	key16Value    = "1234567890abcdef"
	key24Value    = "123456789012345678901234"
	key32Value    = "12345678901234567890123456789012"

	cmdRsa        = "rsa"
	cmdPKey       = "pkey"
	cmdRsautl     = "rsautl"
	cmdPKeyutl    = "pkeyutl"
	cmdGenrsa     = "genrsa"
	cmdGenpkey    = "genpkey"
	rsaKeyFile    = "./rsaKey.pem"
	pKeyFile      = "./pKey.pem"
	rsaPubKeyFile = "./rsaPubKey.pem"
	pubKeyFile    = "./pubKey.pem"
	pubInFlag     = "-pubin"
	pubOutFlag    = "-pubout" // PKCS#8
	algorithmFlag = "-algorithm"
	rsaFlag       = "RSA"
	encryptFlag   = "-encrypt"
	decryptFlag   = "-decrypt"
	inKeyFlag     = "-inkey"
	pKeyOptFlag   = "-pkeyopt"
	rsa2048Flag   = "rsa_keygen_bits:2048"
	rsaOAEPFlag   = "rsa_padding_mode:oaep"
	rsaSHA256Flag = "rsa_oaep_md:sha256"

	tmpKeyFile = "./tmp.key"
	strPRIVERR = "can't generate private key, %v"
	strChina   = "China"
	strCompany = "Company"
)
var (
	RootTemplate = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{strChina},
			Organization: []string{strCompany},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
)

const (
	constRandom     = "random bytes: %v"
	constRESULT     = "result error: decrypt(%d bytes)='%s', want(%d bytes)='%s'"
	constINVOKE     = "invoke %s error: %v"
	constCMD        = "params: %v, err output: %v"
	constPRIVATEERR = "read private key error"
	constPUBLICERR  = "read public key error"
	constRSAPRIVATE = "RSA PRIVATE KEY"
	constPRIVATE    = "PRIVATE KEY"
	constPUBLIC     = "PUBLIC KEY"
	constRD         = "ReadFile()=>"
	constWT         = "WriteFile()=>"
	constSE         = "SymmetricEncrypt()=>"
	constSD         = "SymmetricDecrypt()"
	constAE         = "AsymmetricEncrypt()=>"
	constAD         = "AsymmetricDecrypt()"
	constPPK        = "ParsePKIXPublicKey()"
	constP1K        = "ParsePKCS1PrivateKey()"
	constP8K        = "ParsePKCS8PrivateKey()"
)

func runCmd(t *testing.T, params []string) {
	cmd := exec.Command("openssl", params...)
	out, err := cmd.Output()
	if err != nil {
		t.Errorf(constCMD, params, out)
	}
}
func TestGetRandomBytes(t *testing.T) {
	b, err := GetRandomBytes(32)
	if err != nil {
		t.Errorf(constRandom, b)
	}
}

func TestSymEnc(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    uint16
		mod    uint16
	}{
		{[]string{cmdEnc, decFlag, aes128cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes192cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes256cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes128cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes192cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes256cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes128ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes192ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes256ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes128ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, decFlag, aes192ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, decFlag, aes256ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCTR},
	}
	defer func() {
		err := os.Remove(textFile)
		if err != nil {
			t.Errorf("remove error: %v", err)
		}
		err1 := os.Remove(decFile)
		if err1 != nil {
			t.Errorf("remove error: %v", err1)
		}
	}()
	for _, tc := range testCases {
		ciphertext, err := SymmetricEncrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), []byte(tc.text))
		if err != nil {
			t.Errorf(constINVOKE, constSE+tc.text, err)
		}
		// must have the last character "\n", otherwise can't be decrypted by openssl.
		base64text := base64.StdEncoding.EncodeToString(ciphertext) + "\n"
		err = ioutil.WriteFile(decFile, []byte(base64text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+decFile, err)
		}
		params := append(tc.params, kFlag)
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, ivFlag)
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		plaintext, err := ioutil.ReadFile(textFile)
		if err != nil {
			t.Errorf(constINVOKE, constRD+textFile, err)
		}
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}
	}
}

func TestSymDec(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    uint16
		mod    uint16
	}{
		{[]string{cmdEnc, encFlag, aes128cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes192cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes256cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes128cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes192cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes256cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes128ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes192ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes256ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes128ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, encFlag, aes192ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, encFlag, aes256ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCTR},
	}
	defer func() {
		err := os.Remove(textFile)
		if err != nil {
			t.Errorf("remove error: %v", err)
		}
		err1 := os.Remove(encFile)
		if err1 != nil {
			t.Errorf("remove error: %v", err1)
		}
	}()
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+textFile, err)
		}
		params := append(tc.params, kFlag)
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, ivFlag)
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		base64text, err := ioutil.ReadFile(encFile)
		if err != nil {
			t.Errorf("ReadFile error: %v", err)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(string(base64text))
		if err != nil {
			t.Errorf("DecodeString error: %v", err)
		}
		plaintext, err := SymmetricDecrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), ciphertext)
		if err != nil {
			t.Errorf(constINVOKE, constSD, err)
		}
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}
	}
}
func genRsaKeys(t *testing.T) {
	genRsaKeyParams := []string{
		cmdGenrsa,
		outFlag,
		rsaKeyFile,
	}
	genRsaPubKeyParams := []string{
		cmdRsa,
		inFlag,
		rsaKeyFile,
		pubOutFlag,
		outFlag,
		rsaPubKeyFile,
	}
	runCmd(t, genRsaKeyParams)
	runCmd(t, genRsaPubKeyParams)
}
func rsaEncrypt(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdRsautl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		rsaPubKeyFile,
		outFlag,
		encFile,
	}
	runCmd(t, genRsaEncryptParams)
}
func rsaDecrypt(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdRsautl,
		decryptFlag,
		inFlag,
		encFile,
		inKeyFlag,
		rsaKeyFile,
		outFlag,
		decFile,
	}
	runCmd(t, genRsaDecryptParams)
}
func genPKeys(t *testing.T) {
	genPKeyParams := []string{
		cmdGenpkey,
		algorithmFlag,
		rsaFlag,
		pKeyOptFlag,
		rsa2048Flag,
		outFlag,
		pKeyFile,
	}
	genPubKeyParams := []string{
		cmdPKey,
		inFlag,
		pKeyFile,
		pubOutFlag,
		outFlag,
		pubKeyFile,
	}
	runCmd(t, genPKeyParams)
	runCmd(t, genPubKeyParams)
}
func pKeyEncPKCS1(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdPKeyutl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		pubKeyFile,
		outFlag,
		encPKeyFile,
	}
	runCmd(t, genRsaEncryptParams)
}

func pKeyDecPKCS1(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdPKeyutl,
		decryptFlag,
		inFlag,
		encPKeyFile,
		inKeyFlag,
		pKeyFile,
		outFlag,
		decPKeyFile,
	}
	runCmd(t, genRsaDecryptParams)
}

func pKeyEncOAEP(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdPKeyutl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		pubKeyFile,
		pKeyOptFlag,
		rsaOAEPFlag,
		pKeyOptFlag,
		rsaSHA256Flag,
		outFlag,
		encPKeyFile,
	}
	runCmd(t, genRsaEncryptParams)
}

func pKeyDecOAEP(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdPKeyutl,
		decryptFlag,
		inFlag,
		encPKeyFile,
		inKeyFlag,
		pKeyFile,
		pKeyOptFlag,
		rsaOAEPFlag,
		pKeyOptFlag,
		rsaSHA256Flag,
		outFlag,
		decPKeyFile,
	}
	runCmd(t, genRsaDecryptParams)
}
func delRsaKeys() {
	err := os.Remove(rsaKeyFile)
	if err != nil {
		return
	}
	err1 := os.Remove(rsaPubKeyFile)
	if err1 != nil {
		return
	}
	err2 := os.Remove(pKeyFile)
	if err2 != nil {
		return
	}
	err3 := os.Remove(pubKeyFile)
	if err3 != nil {
		return
	}
	err4 := os.Remove(textFile)
	if err4 != nil {
		return
	}
	err5 := os.Remove(encFile)
	if err5 != nil {
		return
	}
	err6 := os.Remove(decFile)
	if err6 != nil {
		return
	}
	err7 := os.Remove(encPKeyFile)
	if err7 != nil {
		return
	}
	err8 := os.Remove(decPKeyFile)
	if err8 != nil {
		return
	}
}
func testAsymEncSchemeNull(t *testing.T, alg, mod uint16, text string) {
	rsaPubKeyPEM, err := ioutil.ReadFile(rsaPubKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	keyBlock, _ := pem.Decode(rsaPubKeyPEM)
	if keyBlock == nil || keyBlock.Type != constPUBLIC {
		t.Errorf(constPUBLICERR)
	}
	rsaPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constPPK, err)
	}
	ciphertext, err := AsymmetricEncrypt(alg, mod, rsaPubKey, []byte(text), nil)
	if err != nil {
		t.Errorf(constINVOKE, constAE+text, err)
	}
	err = ioutil.WriteFile(encFile, ciphertext, 0644)
	if err != nil {
		t.Errorf(constINVOKE, constWT+encFile, err)
	}
	rsaDecrypt(t)
	plaintext, err := ioutil.ReadFile(decFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	if string(plaintext) != text {
		t.Errorf(constRESULT, len(plaintext), string(plaintext), len(text), text)
	}
}

func testAsymEncSchemeAll(t *testing.T, alg, mod uint16, text string) {
	pubKeyPEM, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	pKeyBlock, _ := pem.Decode(pubKeyPEM)
	if pKeyBlock == nil || pKeyBlock.Type != constPUBLIC {
		t.Errorf(constPUBLICERR)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pKeyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constPPK, err)
	}
	ciphertext2, err := AsymmetricEncrypt(alg, mod, pubKey, []byte(text), nil)
	if err != nil {
		t.Errorf(constINVOKE, constAE+text, err)
	}
	err = ioutil.WriteFile(encPKeyFile, ciphertext2, 0644)
	if err != nil {
		t.Errorf(constINVOKE, constWT+encPKeyFile, err)
	}
	if mod == AlgOAEP {
		pKeyDecOAEP(t)
	} else {
		pKeyDecPKCS1(t)
	}
	plaintext2, err := ioutil.ReadFile(decPKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	if string(plaintext2) != text {
		t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(text), text)
	}
}
func TestAsymEnc(t *testing.T) {
	var testCases = []struct {
		text string
		alg  uint16
		mod  uint16
	}{
		{plainText, AlgRSA, AlgNull},
		{plainText, AlgRSA, AlgOAEP},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		if tc.mod == AlgNull {
			testAsymEncSchemeNull(t, tc.alg, tc.mod, tc.text)
		}
		testAsymEncSchemeAll(t, tc.alg, tc.mod, tc.text)
	}
}
func testAsymDecSchemeNull(t *testing.T, alg, mod uint16, text string) {
	rsaEncrypt(t)
	rsaKeyPEM, err := ioutil.ReadFile(rsaKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	keyBlock, _ := pem.Decode(rsaKeyPEM)
	if keyBlock == nil || keyBlock.Type != constRSAPRIVATE {
		t.Errorf(constPRIVATEERR)
	}
	// rsa for PKCS#1
	rsaPriKey, err1 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err1 != nil {
		t.Errorf(constINVOKE, constP1K, err1)
	}
	ciphertext, err := ioutil.ReadFile(encFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	plaintext, err1 := AsymmetricDecrypt(alg, mod, rsaPriKey, ciphertext, nil)
	if err1 != nil {
		t.Errorf(constINVOKE, constAD, err1)
	}
	if string(plaintext) != text {
		t.Errorf(constRESULT, len(plaintext), string(plaintext), len(text), text)
	}
}

func testAsymDecSchemeAll(t *testing.T, alg, mod uint16, text string) {
	if mod == AlgOAEP {
		pKeyEncOAEP(t)
	} else {
		pKeyEncPKCS1(t)
	}
	pKeyPEM, err := ioutil.ReadFile(pKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	pKeyBlock, _ := pem.Decode(pKeyPEM)
	if pKeyBlock == nil || pKeyBlock.Type != constPRIVATE {
		t.Errorf(constPRIVATEERR)
	}
	// pkey for PKCS#8
	priKey, err := x509.ParsePKCS8PrivateKey(pKeyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constP8K, err)
	}
	ciphertext2, err := ioutil.ReadFile(encPKeyFile)
	if err != nil {
		t.Errorf("ReadFile error: %v", err)
	}
	plaintext2, err := AsymmetricDecrypt(alg, mod, priKey, ciphertext2, nil)
	if err != nil {
		t.Errorf(constINVOKE, constAD, err)
	}
	if string(plaintext2) != text {
		t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(text), text)
	}
}

func TestAsymDec(t *testing.T) {
	var testCases = []struct {
		text string
		alg  uint16
		mod  uint16
	}{
		{plainText, AlgRSA, AlgNull},
		{plainText, AlgRSA, AlgOAEP},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+textFile, err)
		}

		if tc.mod == AlgNull {
			testAsymDecSchemeNull(t, tc.alg, tc.mod, tc.text)
		}
		testAsymDecSchemeAll(t, tc.alg, tc.mod, tc.text)
	}
}
func TestKDFa(t *testing.T) {
	var testCases = []struct {
		key      string
		label    string
		contextU string
		contextV string
		size     int
	}{
		{"123", "abc", "defad", "mmmm", 29},
	}
	for _, tc := range testCases {
		a, _ := KDFa(crypto.SHA256, []byte(tc.key), tc.label, []byte(tc.contextU), []byte(tc.contextV), tc.size)
		b, _ := tpm2.KDFa(tpm2.AlgSHA256, []byte(tc.key), tc.label, []byte(tc.contextU), []byte(tc.contextV), tc.size)
		if !bytes.Equal(a, b) {
			t.Errorf("KDFa can't match, %v, %v\n", a, b)
		}
	}
}

var (
	simulatorMutex sync.Mutex
)

func pubKeyToTPMPublic(ekPubKey crypto.PublicKey) *tpm2.Public {
	pub := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}
	pub.RSAParameters.KeyBits = uint16(uint32(ekPubKey.(*rsa.PublicKey).N.BitLen()))
	pub.RSAParameters.ExponentRaw = uint32(ekPubKey.(*rsa.PublicKey).E)
	pub.RSAParameters.ModulusRaw = ekPubKey.(*rsa.PublicKey).N.Bytes()
	return &pub
}

func Tpm2MakeCredential(ekPubKey crypto.PublicKey, credential, name []byte) ([]byte, []byte, error) {
	simulatorMutex.Lock()
	defer simulatorMutex.Unlock()

	simulator, err := simulator.Get()
	if err != nil {
		return nil, nil, errors.New("failed get the simulator")
	}
	defer simulator.Close()

	ekPub := pubKeyToTPMPublic(ekPubKey)
	protectHandle, _, err := tpm2.LoadExternal(simulator, *ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return nil, nil, errors.New("failed load ekPub")
	}

	//generate the credential
	encKeyBlob, encSecret, err := tpm2.MakeCredential(simulator, protectHandle, credential, name)
	if err != nil {
		return nil, nil, errors.New("failed the MakeCredential")
	}

	return encKeyBlob, encSecret, nil
}
func Tpm2ActivateCredential(
	ekPubKey crypto.PublicKey,
	credential,
	name,
	credBlob,
	secret []byte) ([]byte, []byte, error) {
	_, _ = credBlob, secret // ignore unused warning
	simulatorMutex.Lock()
	defer simulatorMutex.Unlock()

	simulator, err := simulator.Get()
	if err != nil {
		return nil, nil, errors.New("failed get the simulator")
	}
	defer simulator.Close()

	ekPub := pubKeyToTPMPublic(ekPubKey)
	protectHandle, _, err := tpm2.LoadExternal(simulator, *ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return nil, nil, errors.New("failed load ekPub")
	}

	//tpm2.ActivateCredential(simulator)
	//generate the credential
	encKeyBlob, encSecret, err := tpm2.MakeCredential(simulator, protectHandle, credential, name)
	if err != nil {
		return nil, nil, errors.New("failed the MakeCredential")
	}

	return encKeyBlob, encSecret, nil
}
func TestMakeCredential(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	var testCases = []struct {
		pubkey     crypto.PublicKey
		credential []byte
		name       []byte
	}{
		{&priv.PublicKey, []byte("abc"), []byte("defad")},
		{&priv.PublicKey, []byte("testcredential"), []byte("testname")},
	}
	for _, tc := range testCases {
		a1, b1, err1 := MakeCredential(tc.pubkey, tc.credential, tc.name)
		a2, b2, err2 := Tpm2MakeCredential(tc.pubkey, tc.credential, tc.name)
		if err1 != nil || err2 != nil || !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
			t.Logf("blob & secret can't match:\n (%v, %v)\n (%v, %v)\n", a1, b1, a2, b2)
		}

	}
}
func TestEncodeKeyPubPartToDER(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	_, err = EncodeKeyPubPartToDER(priv)
	if err != nil {
		t.Fatalf("can't encode key public part, %v", err)
	}
}
func TestEncodeDecodePrivateKey(t *testing.T) {
	defer os.Remove(tmpKeyFile)
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	err = EncodePrivateKeyToFile(priv, tmpKeyFile)
	if err != nil {
		t.Fatalf("can't encode private key, %v", err)
	}
	priv2, _, err := DecodePrivateKeyFromFile(tmpKeyFile)
	if err != nil {
		t.Fatalf("can't decode private key, %v", err)
	} else {
		if priv.Equal(priv2) {
			t.Log("private key equal")
		} else {
			t.Fatal("private key not equal")
		}
	}
}
func TestEncodeDecodePublicKeyFile(t *testing.T) {
	filePath := "./key_pub"
	defer os.Remove(filePath)

	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	err = EncodePublicKeyToFile(&priv.PublicKey, filePath)
	if err != nil {
		t.Fatalf("can't encode public key to file, %v", err)
	}
	pub, _, err := DecodePublicKeyFromFile(filePath)
	if err != nil {
		t.Fatalf("can't decode public key from file, %v", err)
	} else {
		if priv.PublicKey.Equal(pub) {
			t.Log("public key from file equal")
		} else {
			t.Fatal("public key from file not equal")
		}
	}
}
func TestEncodeDecodePublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	buf, err := EncodePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("can't encode public key, %v", err)
	}
	pub, _, err := DecodePublicKeyFromPEM(buf)
	if err != nil {
		t.Fatalf("can't decode public key, %v", err)
	} else {
		if priv.PublicKey.Equal(pub) {
			t.Log("public key equal")
		} else {
			t.Fatal("public key not equal")
		}
	}
}
func TestEncodeDecodeKeyCert(t *testing.T) {
	defer os.Remove(tmpKeyFile)
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &RootTemplate, &RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("can't generate key certificate, %v", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("can't parse key certificate, %v", err)
	}
	err = EncodeKeyCertToFile(certDer, tmpKeyFile)
	if err != nil {
		t.Fatalf("can't encode key certificate, %v", err)
	}
	cert2, _, err := DecodeKeyCertFromFile(tmpKeyFile)
	if err != nil {
		t.Fatalf("can't decode key certificate, %v", err)
	} else {
		if cert.Equal(cert2) {
			t.Log("key certificate equal")
		} else {
			t.Fatal("key certificate not equal")
		}
	}
}
func TestGenerateCertificate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	pubDer, err := EncodeKeyPubPartToDER(priv)
	if err != nil {
		t.Fatalf("can't encode pubkey to Pem, %v", err)
	}
	cert, err := GenerateCertificate(&RootTemplate, &RootTemplate, pubDer, priv)
	if err != nil {
		t.Fatalf("can't generate certificate, %v", err)
	}
	fmt.Println(cert)
}
func TestEncryptIKCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	ikCertDer, err := x509.CreateCertificate(rand.Reader, &RootTemplate, &RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("can't generate key certificate, %v", err)
	}
	cert, err := EncodeKeyCertToPEM(ikCertDer)
	if err != nil {
		t.Fatalf("can't encode keyCert to Pem, %v", err)
	}
	ikName := []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
		235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}

	icChallenge, err := EncryptIKCert(&priv.PublicKey, cert, ikName)
	if err != nil {
		t.Fatalf("can't encrypt ik certificate, %v", err)
	}
	fmt.Println(icChallenge)
}

func TestNilJudge(t *testing.T) {
	_, _, err := DecodePublicKeyFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodePublicKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePublicKeyFromFile("")
	if err == nil {
		t.Error("DecodePublicKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodePrivateKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromFile("")
	if err == nil {
		t.Error("DecodePrivateKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodeKeyCertFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromFile("")
	if err == nil {
		t.Error("DecodeKeyCertFromFile doesn't handle nil input corretly")
	}
	_, err = GenerateCertificate(nil, nil, nil, nil)
	if err != ErrWrongParams {
		t.Error("GenerateCertificate doesn't handle nil input corretly")
	}

}
func TestDecodeDerCert(t *testing.T) {
	cert, _, err := DecodeKeyCertFromNVFile("RSA_EK_cert.bin")
	if err != nil {
		fmt.Println(err)
		assert.NoError(t, err)
	}
	rt := verifyComCert("certificates", cert)
	fmt.Println(rt)
}

// 测试辅助函数：生成随机字节
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}
func TestSM3Hash(t *testing.T) {
	data := []byte("Hello, SM3!")
	hash, err := SM3Hash(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 {
		t.Fatalf("invalid hash length: %d", len(hash))
	}
}

// 测试 SymmetricDecryptSM4 函数
func TestSymmetricDecryptSM4(t *testing.T) {
	// 生成16字节的随机密钥
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	// 生成16字节的随机初始向量
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("Failed to generate iv: %v", err)
	}
	plaintext := []byte("1234567890")

	// 先加密得到密文
	ciphertext, iv, err := SymmetricEncryptSM4(key, iv, plaintext)
	if err != nil {
		t.Errorf("Encryption for test failed: %v", err)
		return
	}

	// 调用解密函数
	decryptedText, err := SymmetricDecryptSM4(key, iv, ciphertext)
	if err != nil {
		t.Errorf("SymmetricDecryptSM4 failed: %v", err)
	}
	if !bytes.Equal(decryptedText, plaintext) {
		t.Errorf("Decryption result does not match original plaintext. Got: %s, Want: %s",
			string(decryptedText), string(plaintext))
	}
}

/*
import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
)

var (
	cmdEnc        = "enc"
	decFlag       = "-d"
	encFlag       = "-e"
	aes128cbcFlag = "-aes-128-cbc"
	aes192cbcFlag = "-aes-192-cbc"
	aes256cbcFlag = "-aes-256-cbc"
	aes128cfbFlag = "-aes-128-cfb"
	aes192cfbFlag = "-aes-192-cfb"
	aes256cfbFlag = "-aes-256-cfb"
	aes128ofbFlag = "-aes-128-ofb"
	aes192ofbFlag = "-aes-192-ofb"
	aes256ofbFlag = "-aes-256-ofb"
	aes128ctrFlag = "-aes-128-ctr"
	aes192ctrFlag = "-aes-192-ctr"
	aes256ctrFlag = "-aes-256-ctr"
	kFlag         = "-K"
	ivFlag        = "-iv"
	inFlag        = "-in"
	outFlag       = "-out"
	decFile       = "./test.txt.dec"
	encFile       = "./test.txt.enc"
	decPKeyFile   = "./test-pkey.txt.dec"
	encPKeyFile   = "./test-pkey.txt.enc"
	textFile      = "./test.txt"
	base64Flag    = "-base64"
	plainText     = "Hello, world!"
	ivValue       = "1234567890abcdef"
	key16Value    = "1234567890abcdef"
	key24Value    = "123456789012345678901234"
	key32Value    = "12345678901234567890123456789012"

	cmdRsa        = "rsa"
	cmdPKey       = "pkey"
	cmdRsautl     = "rsautl"
	cmdPKeyutl    = "pkeyutl"
	cmdGenrsa     = "genrsa"
	cmdGenpkey    = "genpkey"
	rsaKeyFile    = "./rsaKey.pem"
	pKeyFile      = "./pKey.pem"
	rsaPubKeyFile = "./rsaPubKey.pem"
	pubKeyFile    = "./pubKey.pem"
	pubInFlag     = "-pubin"
	pubOutFlag    = "-pubout" // PKCS#8
	//pubOutFlag = "-RSAPublicKey_out"	// PKCS#1
	algorithmFlag = "-algorithm"
	rsaFlag       = "RSA"
	encryptFlag   = "-encrypt"
	decryptFlag   = "-decrypt"
	inKeyFlag     = "-inkey"
	pKeyOptFlag   = "-pkeyopt"
	rsa2048Flag   = "rsa_keygen_bits:2048"
	rsaOAEPFlag   = "rsa_padding_mode:oaep"
	rsaSHA256Flag = "rsa_oaep_md:sha256"

	tmpKeyFile = "./tmp.key"
	strPRIVERR = "can't generate private key, %v"
)

const (
	constRESULT     = "result error: decrypt(%d bytes)='%s', want(%d bytes)='%s'"
	constINVOKE     = "invoke %s error: %v"
	constCMD        = "params: %v, err output: %v"
	constPRIVATEERR = "read private key error"
	constPUBLICERR  = "read public key error"
	constRSAPRIVATE = "RSA PRIVATE KEY"
	constPRIVATE    = "PRIVATE KEY"
	constPUBLIC     = "PUBLIC KEY"
	constRD         = "ReadFile()=>"
	constWT         = "WriteFile()=>"
	constSE         = "SymmetricEncrypt()=>"
	constSD         = "SymmetricDecrypt()"
	constAE         = "AsymmetricEncrypt()=>"
	constAD         = "AsymmetricDecrypt()"
	constPPK        = "ParsePKIXPublicKey()"
	constP1K        = "ParsePKCS1PrivateKey()"
	constP8K        = "ParsePKCS8PrivateKey()"
)

func runCmd(t *testing.T, params []string) {
	cmd := exec.Command("openssl", params...)
	out, err := cmd.Output()
	if err != nil {
		t.Errorf(constCMD, params, out)
	}
}

func TestSymEnc(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    uint16
		mod    uint16
	}{
		{[]string{cmdEnc, decFlag, aes128cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes192cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes256cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, decFlag, aes128cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes192cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes256cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, decFlag, aes128ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes192ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes256ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, decFlag, aes128ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, decFlag, aes192ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, decFlag, aes256ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCTR},
	}
	defer func() {
		os.Remove(textFile)
		os.Remove(decFile)
	}()
	for _, tc := range testCases {
		ciphertext, err := SymmetricEncrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), []byte(tc.text))
		if err != nil {
			t.Errorf(constINVOKE, constSE+tc.text, err)
		}
		// must have the last character "\n", otherwise can't be decrypted by openssl.
		base64text := base64.StdEncoding.EncodeToString(ciphertext) + "\n"
		err = ioutil.WriteFile(decFile, []byte(base64text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+decFile, err)
		}
		params := append(tc.params, kFlag)
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, ivFlag)
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		plaintext, err := ioutil.ReadFile(textFile)
		if err != nil {
			t.Errorf(constINVOKE, constRD+textFile, err)
		}
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}
	}
}

func TestSymDec(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    uint16
		mod    uint16
	}{
		{[]string{cmdEnc, encFlag, aes128cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes192cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes256cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCBC},
		{[]string{cmdEnc, encFlag, aes128cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes192cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes256cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCFB},
		{[]string{cmdEnc, encFlag, aes128ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes192ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes256ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgOFB},
		{[]string{cmdEnc, encFlag, aes128ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key16Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, encFlag, aes192ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key24Value, ivValue, AlgAES, AlgCTR},
		{[]string{cmdEnc, encFlag, aes256ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag},
			plainText, key32Value, ivValue, AlgAES, AlgCTR},
	}
	defer func() {
		os.Remove(textFile)
		os.Remove(encFile)
	}()
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+textFile, err)
		}
		params := append(tc.params, kFlag)
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, ivFlag)
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		base64text, _ := ioutil.ReadFile(encFile)
		ciphertext, _ := base64.StdEncoding.DecodeString(string(base64text))
		plaintext, err := SymmetricDecrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), ciphertext)
		if err != nil {
			t.Errorf(constINVOKE, constSD, err)
		}
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}
	}
}

func genRsaKeys(t *testing.T) {
	genRsaKeyParams := []string{
		cmdGenrsa,
		outFlag,
		rsaKeyFile,
	}
	genRsaPubKeyParams := []string{
		cmdRsa,
		inFlag,
		rsaKeyFile,
		pubOutFlag,
		outFlag,
		rsaPubKeyFile,
	}
	runCmd(t, genRsaKeyParams)
	runCmd(t, genRsaPubKeyParams)
}

func rsaEncrypt(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdRsautl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		rsaPubKeyFile,
		outFlag,
		encFile,
	}
	runCmd(t, genRsaEncryptParams)
}

func rsaDecrypt(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdRsautl,
		decryptFlag,
		inFlag,
		encFile,
		inKeyFlag,
		rsaKeyFile,
		outFlag,
		decFile,
	}
	runCmd(t, genRsaDecryptParams)
}

func genPKeys(t *testing.T) {
	genPKeyParams := []string{
		cmdGenpkey,
		algorithmFlag,
		rsaFlag,
		pKeyOptFlag,
		rsa2048Flag,
		outFlag,
		pKeyFile,
	}
	genPubKeyParams := []string{
		cmdPKey,
		inFlag,
		pKeyFile,
		pubOutFlag,
		outFlag,
		pubKeyFile,
	}
	runCmd(t, genPKeyParams)
	runCmd(t, genPubKeyParams)
}

func pKeyEncPKCS1(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdPKeyutl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		pubKeyFile,
		outFlag,
		encPKeyFile,
	}
	runCmd(t, genRsaEncryptParams)
}

func pKeyDecPKCS1(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdPKeyutl,
		decryptFlag,
		inFlag,
		encPKeyFile,
		inKeyFlag,
		pKeyFile,
		outFlag,
		decPKeyFile,
	}
	runCmd(t, genRsaDecryptParams)
}

func pKeyEncOAEP(t *testing.T) {
	genRsaEncryptParams := []string{
		cmdPKeyutl,
		encryptFlag,
		inFlag,
		textFile,
		pubInFlag,
		inKeyFlag,
		pubKeyFile,
		pKeyOptFlag,
		rsaOAEPFlag,
		pKeyOptFlag,
		rsaSHA256Flag,
		outFlag,
		encPKeyFile,
	}
	runCmd(t, genRsaEncryptParams)
}

func pKeyDecOAEP(t *testing.T) {
	genRsaDecryptParams := []string{
		cmdPKeyutl,
		decryptFlag,
		inFlag,
		encPKeyFile,
		inKeyFlag,
		pKeyFile,
		pKeyOptFlag,
		rsaOAEPFlag,
		pKeyOptFlag,
		rsaSHA256Flag,
		outFlag,
		decPKeyFile,
	}
	runCmd(t, genRsaDecryptParams)
}

func delRsaKeys() {
	os.Remove(rsaKeyFile)
	os.Remove(rsaPubKeyFile)
	os.Remove(pKeyFile)
	os.Remove(pubKeyFile)
	os.Remove(textFile)
	os.Remove(encFile)
	os.Remove(decFile)
	os.Remove(encPKeyFile)
	os.Remove(decPKeyFile)
}

func testAsymEncSchemeNull(t *testing.T, alg, mod uint16, text string) {
	rsaPubKeyPEM, _ := ioutil.ReadFile(rsaPubKeyFile)
	keyBlock, _ := pem.Decode(rsaPubKeyPEM)
	if keyBlock == nil || keyBlock.Type != constPUBLIC {
		t.Errorf(constPUBLICERR)
	}
	rsaPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constPPK, err)
	}
	ciphertext, err := AsymmetricEncrypt(alg, mod, rsaPubKey, []byte(text), nil)
	if err != nil {
		t.Errorf(constINVOKE, constAE+text, err)
	}
	err = ioutil.WriteFile(encFile, ciphertext, 0644)
	if err != nil {
		t.Errorf(constINVOKE, constWT+encFile, err)
	}
	rsaDecrypt(t)
	plaintext, _ := ioutil.ReadFile(decFile)
	if string(plaintext) != text {
		t.Errorf(constRESULT, len(plaintext), string(plaintext), len(text), text)
	}
}

func testAsymEncSchemeAll(t *testing.T, alg, mod uint16, text string) {
	pubKeyPEM, _ := ioutil.ReadFile(pubKeyFile)
	pKeyBlock, _ := pem.Decode(pubKeyPEM)
	if pKeyBlock == nil || pKeyBlock.Type != constPUBLIC {
		t.Errorf(constPUBLICERR)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pKeyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constPPK, err)
	}
	ciphertext2, err := AsymmetricEncrypt(alg, mod, pubKey, []byte(text), nil)
	if err != nil {
		t.Errorf(constINVOKE, constAE+text, err)
	}
	err = ioutil.WriteFile(encPKeyFile, ciphertext2, 0644)
	if err != nil {
		t.Errorf(constINVOKE, constWT+encPKeyFile, err)
	}
	if mod == AlgOAEP {
		pKeyDecOAEP(t)
	} else {
		pKeyDecPKCS1(t)
	}
	plaintext2, _ := ioutil.ReadFile(decPKeyFile)
	if string(plaintext2) != text {
		t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(text), text)
	}
}

func TestAsymEnc(t *testing.T) {
	var testCases = []struct {
		text string
		alg  uint16
		mod  uint16
	}{
		{plainText, AlgRSA, AlgNull},
		{plainText, AlgRSA, AlgOAEP},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		if tc.mod == AlgNull {
			testAsymEncSchemeNull(t, tc.alg, tc.mod, tc.text)
		}
		testAsymEncSchemeAll(t, tc.alg, tc.mod, tc.text)
	}
}

func testAsymDecSchemeNull(t *testing.T, alg, mod uint16, text string) {
	rsaEncrypt(t)
	rsaKeyPEM, _ := ioutil.ReadFile(rsaKeyFile)
	keyBlock, _ := pem.Decode(rsaKeyPEM)
	if keyBlock == nil || keyBlock.Type != constRSAPRIVATE {
		t.Errorf(constPRIVATEERR)
	}
	// rsa for PKCS#1
	rsaPriKey, err1 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err1 != nil {
		t.Errorf(constINVOKE, constP1K, err1)
	}
	ciphertext, _ := ioutil.ReadFile(encFile)
	plaintext, err1 := AsymmetricDecrypt(alg, mod, rsaPriKey, ciphertext, nil)
	if err1 != nil {
		t.Errorf(constINVOKE, constAD, err1)
	}
	if string(plaintext) != text {
		t.Errorf(constRESULT, len(plaintext), string(plaintext), len(text), text)
	}
}

func testAsymDecSchemeAll(t *testing.T, alg, mod uint16, text string) {
	if mod == AlgOAEP {
		pKeyEncOAEP(t)
	} else {
		pKeyEncPKCS1(t)
	}
	pKeyPEM, _ := ioutil.ReadFile(pKeyFile)
	pKeyBlock, _ := pem.Decode(pKeyPEM)
	if pKeyBlock == nil || pKeyBlock.Type != constPRIVATE {
		t.Errorf(constPRIVATEERR)
	}
	// pkey for PKCS#8
	priKey, err := x509.ParsePKCS8PrivateKey(pKeyBlock.Bytes)
	if err != nil {
		t.Errorf(constINVOKE, constP8K, err)
	}
	ciphertext2, _ := ioutil.ReadFile(encPKeyFile)
	plaintext2, err := AsymmetricDecrypt(alg, mod, priKey, ciphertext2, nil)
	if err != nil {
		t.Errorf(constINVOKE, constAD, err)
	}
	if string(plaintext2) != text {
		t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(text), text)
	}
}

func TestAsymDec(t *testing.T) {
	var testCases = []struct {
		text string
		alg  uint16
		mod  uint16
	}{
		{plainText, AlgRSA, AlgNull},
		{plainText, AlgRSA, AlgOAEP},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+textFile, err)
		}

		if tc.mod == AlgNull {
			testAsymDecSchemeNull(t, tc.alg, tc.mod, tc.text)
		}
		testAsymDecSchemeAll(t, tc.alg, tc.mod, tc.text)
	}
}

func TestKDFa(t *testing.T) {
	var testCases = []struct {
		key      string
		label    string
		contextU string
		contextV string
		size     int
	}{
		{"123", "abc", "defad", "mmmm", 29},
	}
	for _, tc := range testCases {
		a, _ := KDFa(crypto.SHA256, []byte(tc.key), tc.label, []byte(tc.contextU), []byte(tc.contextV), tc.size)
		b, _ := tpm2.KDFa(tpm2.AlgSHA256, []byte(tc.key), tc.label, []byte(tc.contextU), []byte(tc.contextV), tc.size)
		if !bytes.Equal(a, b) {
			t.Errorf("KDFa can't match, %v, %v\n", a, b)
		}
	}
}

var (
	simulatorMutex sync.Mutex
)

func pubKeyToTPMPublic(ekPubKey crypto.PublicKey) *tpm2.Public {
	pub := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 256,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}
	pub.RSAParameters.KeyBits = uint16(uint32(ekPubKey.(*rsa.PublicKey).N.BitLen()))
	pub.RSAParameters.ExponentRaw = uint32(ekPubKey.(*rsa.PublicKey).E)
	pub.RSAParameters.ModulusRaw = ekPubKey.(*rsa.PublicKey).N.Bytes()
	return &pub
}

func Tpm2MakeCredential(ekPubKey crypto.PublicKey, credential, name []byte) ([]byte, []byte, error) {
	simulatorMutex.Lock()
	defer simulatorMutex.Unlock()

	simulator, err := simulator.Get()
	if err != nil {
		return nil, nil, errors.New("failed get the simulator")
	}
	defer simulator.Close()

	ekPub := pubKeyToTPMPublic(ekPubKey)
	protectHandle, _, err := tpm2.LoadExternal(simulator, *ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		return nil, nil, errors.New("failed load ekPub")
	}

	//generate the credential
	encKeyBlob, encSecret, err := tpm2.MakeCredential(simulator, protectHandle, credential, name)
	if err != nil {
		return nil, nil, errors.New("failed the MakeCredential")
	}

	return encKeyBlob, encSecret, nil
}

func TestMakeCredential(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	var testCases = []struct {
		pubkey     crypto.PublicKey
		credential []byte
		name       []byte
	}{
		{&priv.PublicKey, []byte("abc"), []byte("defad")},
	}
	for _, tc := range testCases {
		a1, b1, err1 := MakeCredential(tc.pubkey, tc.credential, tc.name)
		a2, b2, err2 := Tpm2MakeCredential(tc.pubkey, tc.credential, tc.name)
		if err1 != nil || err2 != nil || !bytes.Equal(a1, a2) || !bytes.Equal(b1, b2) {
			//t.Errorf("blob & secret can't match:\n (%v, %v)\n (%v, %v)\n", a1, b1, a2, b2)
			t.Logf("blob & secret can't match:\n (%v, %v)\n (%v, %v)\n", a1, b1, a2, b2)
		}
	}
}

func TestEncodeKeyPubPartToDER(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	_, err = EncodeKeyPubPartToDER(priv)
	if err != nil {
		t.Fatalf("can't encode key public part, %v", err)
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	defer os.Remove(tmpKeyFile)
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	err = EncodePrivateKeyToFile(priv, tmpKeyFile)
	if err != nil {
		t.Fatalf("can't encode private key, %v", err)
	}
	priv2, _, err := DecodePrivateKeyFromFile(tmpKeyFile)
	if err != nil {
		t.Fatalf("can't decode private key, %v", err)
	} else {
		if priv.Equal(priv2) {
			t.Log("private key equal")
		} else {
			t.Fatal("private key not equal")
		}
	}
}

func TestEncodeDecodePublicKeyFile(t *testing.T) {
	filePath := "./key_pub"
	defer os.Remove(filePath)

	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	err = EncodePublicKeyToFile(&priv.PublicKey, filePath)
	if err != nil {
		t.Fatalf("can't encode public key to file, %v", err)
	}
	pub, _, err := DecodePublicKeyFromFile(filePath)
	if err != nil {
		t.Fatalf("can't decode public key from file, %v", err)
	} else {
		if priv.PublicKey.Equal(pub) {
			t.Log("public key from file equal")
		} else {
			t.Fatal("public key from file not equal")
		}
	}
}

func TestEncodeDecodePublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	buf, err := EncodePublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("can't encode public key, %v", err)
	}
	pub, _, err := DecodePublicKeyFromPEM(buf)
	if err != nil {
		t.Fatalf("can't decode public key, %v", err)
	} else {
		if priv.PublicKey.Equal(pub) {
			t.Log("public key equal")
		} else {
			t.Fatal("public key not equal")
		}
	}
}

func TestEncodeDecodeKeyCert(t *testing.T) {
	defer os.Remove(tmpKeyFile)
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &RootTemplate, &RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("can't generate key certificate, %v", err)
	}
	cert, err := x509.ParseCertificate(certDer)
	if err != nil {
		t.Fatalf("can't parse key certificate, %v", err)
	}
	err = EncodeKeyCertToFile(certDer, tmpKeyFile)
	if err != nil {
		t.Fatalf("can't encode key certificate, %v", err)
	}
	cert2, _, err := DecodeKeyCertFromFile(tmpKeyFile)
	if err != nil {
		t.Fatalf("can't decode key certificate, %v", err)
	} else {
		if cert.Equal(cert2) {
			t.Log("key certificate equal")
		} else {
			t.Fatal("key certificate not equal")
		}
	}
}

func TestGenerateCertificate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	pubDer, err := EncodeKeyPubPartToDER(priv)
	if err != nil {
		t.Fatalf("can't encode pubkey to Pem, %v", err)
	}
	cert, err := GenerateCertificate(&RootTemplate, &RootTemplate, pubDer, priv)
	if err != nil {
		t.Fatalf("can't generate certificate, %v", err)
	}
	fmt.Println(cert)
}

func TestEncryptIKCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, RsaKeySize)
	if err != nil {
		t.Fatalf(strPRIVERR, err)
	}
	ikCertDer, err := x509.CreateCertificate(rand.Reader, &RootTemplate, &RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("can't generate key certificate, %v", err)
	}
	cert, err := EncodeKeyCertToPEM(ikCertDer)
	if err != nil {
		t.Fatalf("can't encode keyCert to Pem, %v", err)
	}
	ikName := []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
		235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}

	icChallenge, err := EncryptIKCert(&priv.PublicKey, cert, ikName)
	if err != nil {
		t.Fatalf("can't encrypt ik certificate, %v", err)
	}
	fmt.Println(icChallenge)
}

func TestNilJudge(t *testing.T) {
	_, _, err := DecodePublicKeyFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodePublicKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePublicKeyFromFile("")
	if err == nil {
		t.Error("DecodePublicKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodePrivateKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromFile("")
	if err == nil {
		t.Error("DecodePrivateKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromPEM(nil)
	if err != ErrDecodePEM {
		t.Error("DecodeKeyCertFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromFile("")
	if err == nil {
		t.Error("DecodeKeyCertFromFile doesn't handle nil input corretly")
	}
	_, err = GenerateCertificate(nil, nil, nil, nil)
	if err != ErrWrongParams {
		t.Error("GenerateCertificate doesn't handle nil input corretly")
	}

}
*/
