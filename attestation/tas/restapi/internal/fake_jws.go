/*
This file was duplicated from github.com/deepmap/oapi-codegen/examples/authenticated-api/echo/server/fake_jws.go.
It is used mainly for testing purpose in current project.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package internal

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io/ioutil"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/restapi/internal/ecdsafile"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

// PrivateKey is an ECDSA private key which was generated with the following
// command:
//     openssl ecparam -name prime256v1 -genkey -noout -out ecprivatekey.pem
//
const KeyID = `fake-key-id`
const FakeIssuer = "fake-issuer"
const FakeAudience = "example-users"
const PermissionsClaim = "perm"

type FakeAuthenticator struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	KeySet     jwk.Set
}

// NewFakeAuthenticator creates an authenticator example which uses the ECDSA key
// in the given file to validate JWT's that it has signed itself.
func NewFakeAuthenticator(keyfile string) (*FakeAuthenticator, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	var (
		priv *ecdsa.PrivateKey
		pub  *ecdsa.PublicKey
	)
	if bytes.Contains(key, []byte("PRIVATE KEY")) {
		priv, err = ecdsafile.LoadEcdsaPrivateKey(key)
		if err == nil {
			pub = &priv.PublicKey
		}
	} else if bytes.Contains(key, []byte("PUBLIC KEY")) {
		pub, err = ecdsafile.LoadEcdsaPublicKey(key)
	} else {
		return nil, errors.New("bad key file")
	}
	if err != nil {
		return nil, fmt.Errorf("loading PEM key: %w", err)
	}

	set := jwk.NewSet()
	pubKey := jwk.NewECDSAPublicKey()

	err = pubKey.FromRaw(pub)
	if err != nil {
		return nil, fmt.Errorf("parsing jwk key: %w", err)
	}

	err = pubKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("setting key algorithm: %w", err)
	}

	err = pubKey.Set(jwk.KeyIDKey, KeyID)
	if err != nil {
		return nil, fmt.Errorf("setting key ID: %w", err)
	}

	set.Add(pubKey)

	return &FakeAuthenticator{PrivateKey: priv, PublicKey: pub, KeySet: set}, nil
}

// ValidateJWS ensures that the critical JWT claims needed to ensure that we
// trust the JWT are present and with the correct values.
func (f *FakeAuthenticator) ValidateJWS(jwsString string) (jwt.Token, error) {
	return jwt.Parse([]byte(jwsString), jwt.WithKeySet(f.KeySet))
	//		return jwt.Parse([]byte(jwsString), jwt.WithKeySet(f.KeySet),
	//		jwt.WithAudience(FakeAudience), jwt.WithIssuer(FakeIssuer))
}

// SignToken takes a JWT and signs it with our priviate key, returning a JWS.
func (f *FakeAuthenticator) SignToken(t jwt.Token) ([]byte, error) {
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.AlgorithmKey, jwa.ES256); err != nil {
		return nil, fmt.Errorf("setting algorithm: %w", err)
	}
	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return nil, fmt.Errorf("setting type: %w", err)
	}
	if err := hdr.Set(jws.KeyIDKey, KeyID); err != nil {
		return nil, fmt.Errorf("setting Key ID: %w", err)
	}
	return jwt.Sign(t, jwa.ES256, f.PrivateKey, jwt.WithHeaders(hdr))
}

// CreateJWSWithClaims is a helper function to create JWT's with the specified
// claims.
func (f *FakeAuthenticator) CreateJWSWithClaims(claims []string) ([]byte, error) {
	t := jwt.New()
	err := t.Set(jwt.IssuerKey, FakeIssuer)
	if err != nil {
		return nil, fmt.Errorf("setting issuer: %w", err)
	}
	err = t.Set(jwt.AudienceKey, FakeAudience)
	if err != nil {
		return nil, fmt.Errorf("setting audience: %w", err)
	}
	err = t.Set(PermissionsClaim, claims)
	if err != nil {
		return nil, fmt.Errorf("setting permissions: %w", err)
	}
	return f.SignToken(t)
}
