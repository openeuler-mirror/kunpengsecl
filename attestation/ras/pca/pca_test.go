package pca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
)

const (
	tmpKeyFile = "./tmp.key"
	strPRIVERR = "can't generate private key, %v"
)

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
	if err != errDecodePEM {
		t.Error("DecodePublicKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePublicKeyFromFile("")
	if err == nil {
		t.Error("DecodePublicKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromPEM(nil)
	if err != errDecodePEM {
		t.Error("DecodePrivateKeyFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodePrivateKeyFromFile("")
	if err == nil {
		t.Error("DecodePrivateKeyFromFile doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromPEM(nil)
	if err != errDecodePEM {
		t.Error("DecodeKeyCertFromPEM doesn't handle nil input corretly")
	}
	_, _, err = DecodeKeyCertFromFile("")
	if err == nil {
		t.Error("DecodeKeyCertFromFile doesn't handle nil input corretly")
	}
	_, err = GenerateCertificate(nil, nil, nil, nil)
	if err != errWrongParams {
		t.Error("GenerateCertificate doesn't handle nil input corretly")
	}

}
