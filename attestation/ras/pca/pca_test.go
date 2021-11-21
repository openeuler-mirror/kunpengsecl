package pca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

//test
func TestGenerateCert(t *testing.T) {
	var template = x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"test"},
			Organization: []string{"test"},
			CommonName:   "test CA",
		},
		IsCA: true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		assert.NoError(t, err)
	}
	_, _, err = GenerateCert(&template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)
}
func TestGenerateRootCA(t *testing.T) {
	_, rootPem, _, err := GenerateRootCA()
	fmt.Println("rootCert\n", string(rootPem))
	assert.NoError(t, err)
}
func TestGeneratePCACert(t *testing.T) {
	rootCert, _, rootKey, err := GenerateRootCA()
	assert.NoError(t, err)
	_, _, _, err = GeneratePCACert(rootCert, rootKey)
	assert.NoError(t, err)
}
func TestGetIkCert(t *testing.T) {
	_, err := GetIkCert(CertPEM, PubPEM, nil)
	assert.NoError(t, err)

}
func TestVerifyPCACert(t *testing.T) {
	rootCert, _, rootKey, err := GenerateRootCA()
	assert.NoError(t, err)
	pcaCert, _, _, err := GeneratePCACert(rootCert, rootKey)
	assert.NoError(t, err)
	_, err = verifyPCACert(rootCert, pcaCert)
	assert.NoError(t, err)
}
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
	cert, err := DecodeCert(CertPEM)
	assert.NoError(t, err)
	success := VerifyEkCert(cert)
	assert.False(t, success)
}
func TestGenerateIkCert(t *testing.T) {
	fmt.Println("This is a test of GenerateIkCert")
	rootCert, _, rootKey, err := GenerateRootCA()
	assert.NoError(t, err)
	pcaCert, _, pcaPriv, err := GeneratePCACert(rootCert, rootKey)
	assert.NoError(t, err)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	_, _, err = GenerateIkCert(pcaCert, pcaPriv, &priv.PublicKey)
	assert.NoError(t, err)
}
func TestEncryptAkcert(t *testing.T) {
	var akCert, _ = CreateRandomByte(16)
	akName := []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
		235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}
	_, err := EncryptIkcert(akCert, akName)
	assert.NoError(t, err)
}
