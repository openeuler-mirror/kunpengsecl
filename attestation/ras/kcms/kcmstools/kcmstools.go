// kcmstools package implements the whole process of key caching management service
package kcmstools

import (
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
)

var (
	Cache *cache.Cache
)

func Initialize(deviceId []byte, signCert []byte, teeCert []byte) error {
	// TODO: unmarshal cert to *x509.Certificate

	// TODO: verify signature and cert

	// TODO: save signCert, teeCert to cache

	return nil
}

func GenerateNewKey(taid string, account string, password string) (string, []byte, []byte, error) {
	// TODO: get the trusted status of TA (from cache)

	// TODO: ask KMS to generate a new key for the specific TA, getting (keyid, plaintext, ciphertext)

	// TODO: save information(taid, keyid, ciphertext) of the new key to database

	// TODO: generate a session key K (symmetric, and can only be decryped by KTA)

	// TODO: use K to encrypt plaintext

	// TODO: use cache.signedCert to encrypt K (can only be decryped by KTA))

	// return keyId, ENC(K), ENC(plaintext), error
	return "", nil, nil, nil
}

func GetKey(taid string, account string, passwd string, keyid string) ([]byte, []byte, error) {
	// TODO: get the trusted status of TA (from cache)

	// TODO: find ciphertext of the specific key in database by (taid, keyid)

	// TODO: ask KMS to decrypt ciphertext, getting plaintext

	// TODO: generate a session key K (symmetric, and can only be decryped by KTA)

	// TODO: use K to encrypt plaintext

	// TODO: use cache.signedCert to encrypt K (can only be decryped by KTA))

	// return ENC(K), ENC(plaintext), error
	return nil, nil, nil
}

func DeleteKey(taid string, keyid string) error {
	// TODO: get the trusted status of TA (from cache)

	// TODO: delete the specific key in database

	return nil
}
