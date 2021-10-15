package pca

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

//test

var req = Request{
	TPMVer: "2.0",

}

func TestPCAForUnsupportedTpm(t *testing.T) {
	//测试TPM的版本
	req.TPMVer = "1.0"
	_,err := NewPCA(req)
	assert.Error(t, err)
}
func TestVerifyEkCert(t *testing.T){
	fmt.Println("This is a test of VerifyEkCert")

	var ekcert x509.Certificate
	pca,err := NewPCA(req)
	if err!=nil{
		errors.New("Create a new pca Error")
	}

	Bool,_:=pca.VerifyEkCert(ekcert)
	if !Bool{
		fmt.Println("Verify EkCert is failed!")
	}else{
		fmt.Println("Verify EkCert is success!")
	}
}
func TestGenerateAkCert(t *testing.T) {
	fmt.Println("This is a test of GenerateAkCert")
	//
	var pcaPriv crypto.PrivateKey
	//var pcaPub crypto.PublicKey
	var pcaCert *x509.Certificate
	var akPub rsa.PublicKey
	_,err := GenerateAkCert(pcaPriv,pcaCert,akPub)
	assert.NoError(t, err)
}
func TestEncryptAkcert(t *testing.T) {
	var akCert,_ = CreateRandomByte(16)
	akName:=[]byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
	235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252}
	_,err := EncryptAkcert(akCert,akName)
	assert.NoError(t, err)
}
