package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

func initRestapiAuthKeyFile(privfile string, pubfile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pubkey := &key.PublicKey

	kbs, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kbs})

	kbs, err = x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: kbs})

	err = ioutil.WriteFile(privfile, privPEM, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(pubfile, pubPEM, 0644)
	if err != nil {
		return err
	}

	return nil
}

var (
	priv string
	pub  string
)

func CreateAuthKeyFile(privfile string, pubfile string) {
	priv, pub = privfile, pubfile
	initRestapiAuthKeyFile(priv, pub)
}

func RemoveAuthKeyFile() {
	os.Remove(priv)
	os.Remove(pub)
}
