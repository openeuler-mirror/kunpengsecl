package pca

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/google/go-tpm/tpm2"
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
		{[]string{"enc", "-d", "-aes-128-cbc", "-in", "test.txt.dec", "-out", "test.txt", "-base64"}, "Hello, world!", "1234567890abcdef", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{"enc", "-d", "-aes-192-cbc", "-in", "test.txt.dec", "-out", "test.txt", "-base64"}, "Hello, world!", "123456789012345678901234", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{"enc", "-d", "-aes-256-cbc", "-in", "test.txt.dec", "-out", "test.txt", "-base64"}, "Hello, world!", "12345678901234567890123456789012", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
	}
	defer func() {
		os.Remove("./test.txt")
		os.Remove("./test.txt.dec")
	}()
	for _, tc := range testCases {
		ciphertext, err := SymmetricEncrypt(tc.alg, tc.mod, []byte(tc.key), []byte(tc.iv), []byte(tc.text))
		if err != nil {
			t.Errorf("%v", err)
		}
		// must have the last character "\n", otherwise can't be decrypted by openssl.
		base64text := base64.StdEncoding.EncodeToString(ciphertext) + "\n"
		err = ioutil.WriteFile("./test.txt.dec", []byte(base64text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		cmd := exec.Command("openssl", params...)
		var out bytes.Buffer
		cmd.Stderr = &out
		if err = cmd.Run(); err != nil {
			t.Errorf("couldn't run command %v", out.String())
		}
		plaintext, err := ioutil.ReadFile("./test.txt")
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
		{[]string{"enc", "-e", "-aes-128-cbc", "-in", "test.txt", "-out", "test.txt.enc", "-base64"}, "Hello, world!", "1234567890abcdef", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{"enc", "-e", "-aes-192-cbc", "-in", "test.txt", "-out", "test.txt.enc", "-base64"}, "Hello, world!", "123456789012345678901234", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
		{[]string{"enc", "-e", "-aes-256-cbc", "-in", "test.txt", "-out", "test.txt.enc", "-base64"}, "Hello, world!", "12345678901234567890123456789012", "1234567890abcdef", tpm2.AlgAES, tpm2.AlgCBC},
	}
	defer func() {
		os.Remove("./test.txt")
		os.Remove("./test.txt.enc")
	}()
	for _, tc := range testCases {
		err := ioutil.WriteFile("./test.txt", []byte(tc.text), 0644)
		if err != nil {
			t.Errorf("couldn't write test file %v", err)
		}
		params := append(tc.params, "-K")
		params = append(params, hex.EncodeToString([]byte(tc.key)))
		params = append(params, "-iv")
		params = append(params, hex.EncodeToString([]byte(tc.iv)))
		cmd := exec.Command("openssl", params...)
		var out bytes.Buffer
		cmd.Stderr = &out
		if err = cmd.Run(); err != nil {
			t.Errorf("couldn't run command %v", out.String())
		}
		base64text, _ := ioutil.ReadFile("./test.txt.enc")
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
