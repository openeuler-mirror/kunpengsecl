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
	rootCert, rootPem, rootKey, err := GenerateRootCA()
	assert.NoError(t, err)
	fmt.Println("rootCert\n", string(rootPem))
	rootPrivPem, err := EncodePrivKeyAsPemStr(rootKey)
	assert.NoError(t, err)
	fmt.Println("rootKey\n", string(rootPrivPem))
	_, pem, priv, err := GeneratePCACert(rootCert, rootKey)
	assert.NoError(t, err)
	fmt.Println("Cert\n", string(pem))
	privPem, err := EncodePrivKeyAsPemStr(priv)
	assert.NoError(t, err)
	fmt.Println("Key\n", string(privPem))
}
func TestGenerateSignature(t *testing.T) {
	_, _, _, err := GenerateSignature([]byte(CertPEM))
	assert.NoError(t, err)
}
func TestVerifySigAndPub(t *testing.T) {
	sig, hash, pub, err := GenerateSignature([]byte(CertPEM))
	assert.NoError(t, err)
	ok := VerifySigAndPub(sig, hash, pub)
	assert.NoError(t, ok)
}
func TestGetIkCert(t *testing.T) {
	_, err := GetIkCert(CertPEM, PubPEM, nil)
	assert.NoError(t, err)
}

func TestVerifyPCACert(t *testing.T) {
	_, rootPEM, rootKey, err := GenerateRootCA()
	assert.NoError(t, err)
	rootCert, err := DecodeCert(string(rootPEM))
	assert.NoError(t, err)
	rootPrivPEM, err := EncodePrivKeyAsPemStr(rootKey)
	assert.NoError(t, err)
	rootPriv, err := DecodePrivkey(rootPrivPEM)
	assert.NoError(t, err)
	pcaCert, _, _, err := GeneratePCACert(rootCert, rootPriv)
	assert.NoError(t, err)
	_, err = verifyPCACert(rootCert, pcaCert)
	assert.NoError(t, err)
}

func TestVerifyCert(t *testing.T) {
	pcaCert, err := DecodeCert(string(CertPEM))
	assert.NoError(t, err)
	pcaPriv, err := DecodePrivkey(PrivPEM)
	assert.NoError(t, err)
	cert, _, _, err := GeneratePCACert(pcaCert, pcaPriv)
	assert.NoError(t, err)
	_, err = verifyPCACert(pcaCert, cert)
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
func TestDecodePrivKey(t *testing.T) {
	_, err := DecodePrivkey(PrivPEM)
	assert.NoError(t, err)
}
func TestGenerateRsaKey(t *testing.T) {
	_, _, err := GenerateRsaKey()
	assert.NoError(t, err)
}
func TestEncodePrivKeyAsPemStr(t *testing.T) {
	priv, _, err := GenerateRsaKey()
	assert.NoError(t, err)
	privPem, err := EncodePrivKeyAsPemStr(priv)
	fmt.Println(privPem)
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
	var ikCert, _ = CreateRandomBytes(16)
	akName := []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
		235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}
	pub, err := DecodePubkey(PubRSA2048)
	assert.NoError(t, err)
	_, err = EncryptIkcert(pub, ikCert, akName)
	assert.NoError(t, err)
}
