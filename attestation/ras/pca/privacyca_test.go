package pca

import (
	"encoding/base64"
	"encoding/hex"
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
	decFileFlag   = "./test.txt.dec"
	encFileFlag   = "./test.txt.enc"
	outFlag       = "-out"
	textFileFlag  = "./test.txt"
	base64Flag    = "-base64"
	plainText     = "Hello, world!"
	ivFlag        = "1234567890abcdef"
	key16Flag     = "1234567890abcdef"
	key24Flag     = "123456789012345678901234"
	key32Flag     = "12345678901234567890123456789012"
)

func TestSymmetricEncrypt(t *testing.T) {
	var testCases = []struct {
		params []string
		text   string
		key    string
		iv     string
		alg    tpm2.Algorithm
		mod    tpm2.Algorithm
	}{
		{[]string{cmdEnc, decFlag, aes128cbcFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes192cbcFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes256cbcFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, decFlag, aes128cfbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes192cfbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes256cfbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, decFlag, aes128ofbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes192ofbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes256ofbFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, decFlag, aes128ctrFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes192ctrFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, decFlag, aes256ctrFlag, inFlag, decFileFlag, outFlag, textFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
	}
	defer func() {
		os.Remove(textFileFlag)
		os.Remove(decFileFlag)
	}()
	for _, tc := range testCases {
		ciphertext, err := SymmetricEncrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), []byte(tc.text))
		if err != nil {
			t.Errorf("%v", err)
		}
		// must have the last character "\n", otherwise can't be decrypted by openssl.
		base64text := base64.StdEncoding.EncodeToString(ciphertext) + "\n"
		err = ioutil.WriteFile(decFileFlag, []byte(base64text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		cmd := exec.Command("openssl", params...)
		if out, err := cmd.Output(); err != nil {
			t.Errorf("couldn't run command %v", out)
		}
		plaintext, err := ioutil.ReadFile(textFileFlag)
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
		{[]string{cmdEnc, encFlag, aes128cbcFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes192cbcFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes256cbcFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{cmdEnc, encFlag, aes128cfbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes192cfbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes256cfbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCFB},
		{[]string{cmdEnc, encFlag, aes128ofbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes192ofbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes256ofbFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgOFB},
		{[]string{cmdEnc, encFlag, aes128ctrFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key16Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes192ctrFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key24Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
		{[]string{cmdEnc, encFlag, aes256ctrFlag, inFlag, textFileFlag, outFlag, encFileFlag, base64Flag}, plainText, key32Flag, ivFlag, tpm2.AlgAES, tpm2.AlgCTR},
	}
	defer func() {
		os.Remove(textFileFlag)
		os.Remove(encFileFlag)
	}()
	for _, tc := range testCases {
		err := ioutil.WriteFile(textFileFlag, []byte(tc.text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		cmd := exec.Command("openssl", params...)
		if out, err := cmd.Output(); err != nil {
			t.Errorf("couldn't run command %v", out)
		}
		base64text, _ := ioutil.ReadFile(encFileFlag)
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
