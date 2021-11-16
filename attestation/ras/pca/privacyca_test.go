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
	inFlag        = "-in"
	decFile       = "./test.txt.dec"
	encFile       = "./test.txt.enc"
	outFlag       = "-out"
	textFile      = "./test.txt"
	base64Flag    = "-base64"
	plainText     = "Hello, world!"
	ivFlag        = "1234567890abcdef"
	key16Flag     = "1234567890abcdef"
	key24Flag     = "123456789012345678901234"
	key32Flag     = "12345678901234567890123456789012"

	cmdRsa        = "rsa"
	cmdRsautl     = "rsautl"
	cmdGenrsa     = "genrsa"
	rsaKeyFile    = "./rsaKey.pem"
	rsaPubKeyFile = "./rsaPubKey.pem"
	rsaPubOutFlag = "-pubout" // PKCS#8
	//rsaPubOutFlag = "-RSAPublicKey_out"	// PKCS#1
	encryptFlag = "-encrypt"
	decryptFlag = "-decrypt"
	inKeyFlag   = "-inkey"
	pubInFlag   = "-pubin"
)

func runCmd(t *testing.T, params []string) {
	cmd := exec.Command("openssl", params...)
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("couldn't run command %v", out)
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
		{[]string{cmdEnc, decFlag, aes128cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes192cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes256cbcFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes128cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes192cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes256cfbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes128ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes192ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes256ofbFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes128ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes192ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes256ctrFlag, inFlag, decFile, outFlag, textFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
	}
	defer func() {
		os.Remove(textFile)
		os.Remove(decFile)
	}()
	for _, tc := range testCases {
		ciphertext, err := SymmetricEncrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), []byte(tc.text))
		if err != nil {
			t.Errorf("%v", err)
		}
		// must have the last character "\n", otherwise can't be decrypted by openssl.
		base64text := base64.StdEncoding.EncodeToString(ciphertext) + "\n"
		err = ioutil.WriteFile(decFile, []byte(base64text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		plaintext, err := ioutil.ReadFile(textFile)
		if err != nil {
			t.Errorf("couldn't read test file %v", err)
		}
		if string(plaintext) != tc.text {
			t.Errorf("error: decrypt(%d bytes)='%s', want(%d bytes)='%s'\n", len(plaintext), string(plaintext), len(tc.text), tc.text)
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
		{[]string{cmdEnc, encFlag, aes128cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes192cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes256cbcFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes128cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes192cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes256cfbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes128ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes192ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes256ofbFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes128ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes192ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes256ctrFlag, inFlag, textFile, outFlag, encFile, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
	}
	defer func() {
		os.Remove(textFile)
		os.Remove(encFile)
	}()
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		runCmd(t, params)
		base64text, _ := ioutil.ReadFile(encFile)
		ciphertext, _ := base64.StdEncoding.DecodeString(string(base64text))
		plaintext, err := SymmetricDecrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), ciphertext)
		if err != nil {
			t.Errorf("%v", err)
		}
		if string(plaintext) != tc.text {
			t.Errorf("error: decrypt(%d bytes)='%s', want(%d bytes)='%s'\n", len(plaintext), string(plaintext), len(tc.text), tc.text)
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
		rsaPubOutFlag,
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

func delRsaKeys() {
	os.Remove(rsaKeyFile)
	os.Remove(rsaPubKeyFile)
	os.Remove(textFile)
	os.Remove(encFile)
	os.Remove(decFile)
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
	for _, tc := range testCases {
		rsaPubKeyPEM, _ := ioutil.ReadFile(rsaPubKeyFile)
		keyBlock, _ := pem.Decode(rsaPubKeyPEM)
		if keyBlock == nil || keyBlock.Type != "PUBLIC KEY" {
			t.Errorf("read rsa public key error")
		}
		rsaPubKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
		if err != nil {
			t.Errorf("couldn't parse public key %v", err)
		}
		ciphertext, err := AsymmetricEncrypt(tc.alg, tc.mod, rsaPubKey, []byte(tc.text), nil)
		if err != nil {
			t.Errorf("couldn't do AsymmetricEncrypt %v", err)
		}
		err = ioutil.WriteFile(encFile, ciphertext, 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		rsaDecrypt(t)
		plaintext, _ := ioutil.ReadFile(decFile)
		if string(plaintext) != tc.text {
			t.Errorf("error: decrypt(%d bytes)='%s', want(%d bytes)='%s'\n", len(plaintext), string(plaintext), len(tc.text), tc.text)
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
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFile, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		rsaEncrypt(t)
		rsaKeyPEM, _ := ioutil.ReadFile(rsaKeyFile)
		keyBlock, _ := pem.Decode(rsaKeyPEM)
		if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
			t.Errorf("read rsa key error")
		}
		rsaPriKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Errorf("couldn't parse private key %v", err)
		}
		ciphertext, _ := ioutil.ReadFile(encFile)
		plaintext, err := AsymmetricDecrypt(tc.alg, tc.mod, rsaPriKey, ciphertext, nil)
		if err != nil {
			t.Errorf("couldn't do AsymmetricDecrypt %v", err)
		}
		if string(plaintext) != tc.text {
			t.Errorf("error: decrypt(%d bytes)='%s', want(%d bytes)='%s'\n", len(plaintext), string(plaintext), len(tc.text), tc.text)
		}
	}
}
