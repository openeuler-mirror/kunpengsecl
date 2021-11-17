package pca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

//test

func TestDecodeCert(t *testing.T) {
	_, err := DecodeCert(CertPEM)
	assert.NoError(t, err)
}
func TestDecodePubkey(t *testing.T) {
	_, err := DecodePubkey(PubPEM)
	assert.NoError(t, err)
}
func TestPCAForUnsupportedTpm(t *testing.T) {
	//测试TPM的版本
	req := Request{
		TPMVer: "1.0",
	}

	_, err := NewPCA(req)
	assert.Error(t, err)
}
func TestVerifyEkCert(t *testing.T) {
	fmt.Println("This is a test of VerifyEkCert")
	cert,err := DecodeCert(CertPEM)
	assert.NoError(t, err)
	success := VerifyEkCert(cert)
	assert.False(t, success)
}
func TestGenerateAkCert(t *testing.T) {
	fmt.Println("This is a test of GenerateAkCert")
	//
	var pcaPriv crypto.PrivateKey
	//var pcaPub crypto.PublicKey
	var pcaCert *x509.Certificate
	var akPub rsa.PublicKey
	_, err := GenerateAkCert(pcaPriv, pcaCert, akPub)
	assert.Error(t, err)
}
func TestEncryptAkcert(t *testing.T) {
	var akCert, _ = CreateRandomByte(16)
	akName := []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
		235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}
	_, err := EncryptAkcert(akCert, akName)
	assert.NoError(t, err)
}
