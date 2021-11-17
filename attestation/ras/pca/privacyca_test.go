package pca

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

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

func TestSymmetricEncrypt(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    tpm2.Algorithm
		mod    tpm2.Algorithm
	}{
		{[]string{cmdEnc, decFlag, aes128cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes192cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes256cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes128cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes192cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes256cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes128ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes192ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes256ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes128ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes192ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes256ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
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

func TestSymmetricDecrypt(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    tpm2.Algorithm
		mod    tpm2.Algorithm
	}{
		{[]string{cmdEnc, encFlag, aes128cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes192cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes256cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes128cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes192cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes256cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes128ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes192ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes256ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes128ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes192ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes256ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Value, ivValue, tpm2.AlgAES, tpm2.AlgCTR},
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

func pKeyEncrypt(t *testing.T) {
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

func pKeyDecrypt(t *testing.T) {
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

func TestAsymmetricEncrypt(t *testing.T) {
	var testCases = []struct {
		text string
		alg  tpm2.Algorithm
		mod  tpm2.Algorithm
	}{
		{plainText, tpm2.AlgRSA, tpm2.AlgNull},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		rsaPubKeyPEM, _ := ioutil.ReadFile(rsaPubKeyFile)
		keyBlock, _ := pem.Decode(rsaPubKeyPEM)
		if keyBlock == nil || keyBlock.Type != constPUBLIC {
			t.Errorf(constPUBLICERR)
		}
		rsaPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
		if err != nil {
			t.Errorf(constINVOKE, constPPK, err)
		}
		ciphertext, err := AsymmetricEncrypt(tc.alg, tc.mod, rsaPubKey, []byte(tc.text), nil)
		if err != nil {
			t.Errorf(constINVOKE, constAE+tc.text, err)
		}
		err = ioutil.WriteFile(encFile, ciphertext, 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+encFile, err)
		}
		rsaDecrypt(t)
		plaintext, _ := ioutil.ReadFile(decFile)
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}

		pubKeyPEM, _ := ioutil.ReadFile(pubKeyFile)
		pKeyBlock, _ := pem.Decode(pubKeyPEM)
		if pKeyBlock == nil || pKeyBlock.Type != constPUBLIC {
			t.Errorf(constPUBLICERR)
		}
		pubKey, err := x509.ParsePKIXPublicKey(pKeyBlock.Bytes)
		if err != nil {
			t.Errorf(constINVOKE, constPPK, err)
		}
		ciphertext2, err := AsymmetricEncrypt(tc.alg, tc.mod, pubKey, []byte(tc.text), nil)
		if err != nil {
			t.Errorf(constINVOKE, constAE+tc.text, err)
		}
		err = ioutil.WriteFile(encPKeyFile, ciphertext2, 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+encPKeyFile, err)
		}
		pKeyDecrypt(t)
		plaintext2, _ := ioutil.ReadFile(decPKeyFile)
		if string(plaintext2) != tc.text {
			t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(tc.text), tc.text)
		}
	}
}

func TestAsymmetricDecrypt(t *testing.T) {
	var testCases = []struct {
		text string
		alg  tpm2.Algorithm
		mod  tpm2.Algorithm
	}{
		{plainText, tpm2.AlgRSA, tpm2.AlgNull},
	}
	defer delRsaKeys()
	genRsaKeys(t)
	genPKeys(t)
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf(constINVOKE, constWT+textFile, err)
		}

		rsaEncrypt(t)
		rsaKeyPEM, _ := ioutil.ReadFile(rsaKeyFile)
		keyBlock, _ := pem.Decode(rsaKeyPEM)
		if keyBlock == nil || keyBlock.Type != constRSAPRIVATE {
			t.Errorf(constPRIVATEERR)
		}
		// rsa for PKCS#1
		rsaPriKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Errorf(constINVOKE, constP1K, err)
		}
		ciphertext, _ := ioutil.ReadFile(encFile)
		plaintext, err := AsymmetricDecrypt(tc.alg, tc.mod, rsaPriKey, ciphertext, nil)
		if err != nil {
			t.Errorf(constINVOKE, constAD, err)
		}
		if string(plaintext) != tc.text {
			t.Errorf(constRESULT, len(plaintext), string(plaintext), len(tc.text), tc.text)
		}

		pKeyEncrypt(t)
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
		plaintext2, err := AsymmetricDecrypt(tc.alg, tc.mod, priKey, ciphertext2, nil)
		if err != nil {
			t.Errorf(constINVOKE, constAD, err)
		}
		if string(plaintext2) != tc.text {
			t.Errorf(constRESULT, len(plaintext2), string(plaintext2), len(tc.text), tc.text)
		}
	}
}
