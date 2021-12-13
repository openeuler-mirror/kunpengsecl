/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: lixinda
Create: 2021-09-17
Modify by: wucaijun
Modify at: 2021-12-07
Description: key/certificate handle functions for privacy ca.
*/

package pca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
)

const (
	Encrypt_Alg    = "AES128-CBC"
	AesKeySize     = 16
	RsaKeySize     = 2048
	headPrivKey    = "PRIVATE KEY"
	headPubKey     = "PUBLIC KEY"
	headRsaPrivKey = "RSA PRIVATE KEY"
	headRsaPubKey  = "RSA PUBLIC KEY"
	modKey         = 0600
	headCert       = "CERTIFICATE"
	modCert        = 0644
	strChina       = "China"
	strCompany     = "Company"
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
		//IPAddresses:         []net.IP{net.ParseIP(caIP)},
	}

	PcaTemplate = x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject: pkix.Name{
			Country:      []string{strChina},
			Organization: []string{strCompany},
			CommonName:   "privacy ca",
		},
		NotBefore:             time.Now().Add(-10 * time.Second),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
		MaxPathLen:            1,
		//IPAddresses:           []net.IP{net.ParseIP(caIP)},
	}

	// error definition
	errEncodeDER   = errors.New("failed to encode DER []byte")
	errEncodePEM   = errors.New("failed to encode PEM information")
	errDecodePEM   = errors.New("failed to decode PEM information")
	errParseKey    = errors.New("failed to parse the key")
	errWrongParams = errors.New("wrong input parameter")
)

func EncodeKeyPubPartToDER(key crypto.PrivateKey) ([]byte, error) {
	var err error
	var derData []byte
	switch priv := key.(type) {
	case *rsa.PrivateKey:
		derData, err = x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return nil, err
		}
		return derData, nil
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	}
	return derData, errEncodeDER
}

// EncodePublicKeyToPEM encodes the public key to a pem []byte
func EncodePublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	var pemData []byte
	switch pub.(type) {
	case *rsa.PublicKey:
		derBuf, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		pemData = pem.EncodeToMemory(
			&pem.Block{
				Type:  headPubKey,
				Bytes: derBuf,
			},
		)
		return pemData, nil
	case *ecdsa.PublicKey:
	case ed25519.PublicKey:
	}
	return nil, errEncodePEM
}

// EncodePublicKeyToFile encodes the public key to a file as pem format
func EncodePublicKeyToFile(pub crypto.PublicKey, fileName string) error {
	data, _ := EncodePublicKeyToPEM(pub)
	return ioutil.WriteFile(fileName, data, modKey)
}

// EncodePrivateKeyToPEM encodes the private key to a pem []byte
func EncodePrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error) {
	var pemData []byte
	switch priv.(type) {
	case *rsa.PrivateKey:
		derBuf, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemData = pem.EncodeToMemory(
			&pem.Block{
				Type:  headPrivKey,
				Bytes: derBuf,
			},
		)
		return pemData, nil
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	}
	return nil, errEncodePEM
}

// EncodePrivateKeyToFile encodes the private key to a file as pem format
func EncodePrivateKeyToFile(priv crypto.PrivateKey, fileName string) error {
	data, _ := EncodePrivateKeyToPEM(priv)
	return ioutil.WriteFile(fileName, data, modKey)
}

// EncodeKeyCertToPEM encodes the der form key certificate to a pem []byte
func EncodeKeyCertToPEM(certDer []byte) ([]byte, error) {
	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  headCert,
			Bytes: certDer,
		},
	)
	return pemData, nil
}

// EncodeKeyCertToFile encodes the der form key certificate to a pem file
func EncodeKeyCertToFile(certDer []byte, fileName string) error {
	data, err := EncodeKeyCertToPEM(certDer)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, data, modCert)
}

// DecodePublicKeyFromPEM decodes a pem []byte to get the public key
func DecodePublicKeyFromPEM(pemData []byte) (crypto.PublicKey, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != headPubKey {
		return nil, nil, errDecodePEM
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, errParseKey
	}
	return pub, block.Bytes, nil
}

// DecodePublicKeyFromFile decodes a pem file to get the public key
func DecodePublicKeyFromFile(fileName string) (crypto.PublicKey, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodePublicKeyFromPEM(data)
}

// DecodePrivateKeyFromPEM decodes a pem []byte to get the private key
func DecodePrivateKeyFromPEM(pemData []byte) (crypto.PrivateKey, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != headPrivKey {
		return nil, nil, errDecodePEM
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errParseKey
	}
	return priv, block.Bytes, nil
}

// DecodePrivateKeyFromFile decodes a pem file to get the private key
func DecodePrivateKeyFromFile(fileName string) (crypto.PrivateKey, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodePrivateKeyFromPEM(data)
}

// DecodeKeyCertFromPEM decodes the key certificate from a pem format []byte
func DecodeKeyCertFromPEM(pemData []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, errDecodePEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, errParseKey
	}
	return cert, block.Bytes, nil
}

// DecodeKeyCertFromFile decodes a pem file to get the key certificate
func DecodeKeyCertFromFile(fileName string) (*x509.Certificate, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodeKeyCertFromPEM(data)
}

// GenerateCertificate generate a certificate according to template, signed by signer parent/key
func GenerateCertificate(template, parent *x509.Certificate, pubDer []byte, signer crypto.PrivateKey) ([]byte, error) {
	if template == nil || parent == nil || len(pubDer) == 0 || signer == nil {
		return nil, errWrongParams
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubDer)
	if err != nil {
		return nil, err
	}
	certDer, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signer)
	if err != nil {
		return nil, err
	}
	return certDer, nil
}

// replace part one: start
var (
	simulatorMutex sync.Mutex
)

func pubKeyToTPMPublic(ekPubKey crypto.PublicKey) *tpm2.Public {
	pub := DefaultKeyParams
	pub.RSAParameters.KeyBits = uint16(uint32(ekPubKey.(*rsa.PublicKey).N.BitLen()))
	pub.RSAParameters.ExponentRaw = uint32(ekPubKey.(*rsa.PublicKey).E)
	pub.RSAParameters.ModulusRaw = ekPubKey.(*rsa.PublicKey).N.Bytes()
	return &pub
}

// replace part one: end

func EncryptIKCert(ekPubKey crypto.PublicKey, ikCert []byte, ikName []byte) (*IKCertChallenge, error) {
	key, _ := GetRandomBytes(AesKeySize)
	iv, _ := GetRandomBytes(AesKeySize)
	encIKCert, err := SymmetricEncrypt(AlgAES, AlgCBC, key, iv, ikCert)
	if err != nil {
		return nil, err
	}

	// replace part two: start
	simulatorMutex.Lock()
	defer simulatorMutex.Unlock()

	simulator, err := simulator.Get()
	if err != nil {
		return nil, errors.New("failed get the simulator")
	}
	defer simulator.Close()

	ekPub := pubKeyToTPMPublic(ekPubKey)
	protectHandle, _, err := tpm2.LoadExternal(simulator, *ekPub, tpm2.Private{}, tpm2.HandleNull)
	if err != nil {
		log.Println(err)
		return nil, errors.New("failed load ekPub")
	}

	//generate the credential
	encKeyBlob, encSecret, err := tpm2.MakeCredential(simulator, protectHandle, key, ikName)
	if err != nil {
		return nil, errors.New("failed the MakeCredential")
	}
	// replace part two: end

	// use this block to replace the upper "tpm2.MakeCredential" two parts!!!
	/*
		encKeyBlob, encSecret, err := MakeCredential(ekPubKey, key, ikName)
		if err != nil {
			return nil, err
		}
	*/

	symKeyParams := SymKeyParams{
		// encrypted secret by ekPub, use tpm2.ActivateCredential to decrypt and get secret
		EncryptedSecret: encSecret,
		// encrypted key by secret, use AES128 CFB to decrypt and get key
		CredBlob: encKeyBlob,
		// use this algorithm(AES128 CBC) + iv + key to decrypt ikCret
		EncryptAlg:   Encrypt_Alg,
		EncryptParam: iv,
	}
	ikCertChallenge := IKCertChallenge{
		// encrypted ikCert by key
		EncryptedCert: encIKCert,
		SymKeyParams:  symKeyParams,
	}
	return &ikCertChallenge, nil
}
