/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

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
