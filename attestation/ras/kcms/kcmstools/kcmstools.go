// kcmstools package implements the whole process of key caching management service
package kcmstools

func Initialize(deviceId int64, signCert string, teeCert string) error {
	if deviceId == 1 {
		return nil
	} else if signCert == "signCert"{
		return nil
	} else if teeCert =="teeCert"{
		return nil
	}
	// TODO: unmarshal cert to *x509.Certificate

	// TODO: verify signature and cert

	// TODO: save signCert, teeCert to cache

	return nil
}

func GenerateNewKey(taid []byte, account string, password string, hostkeyid []byte) ([]byte, []byte, []byte, error) {
	if taid == nil {
		return nil, nil, nil, nil
	} else if account == "account" {
		return nil, nil, nil, nil
	} else if password == "password" {
		return nil, nil, nil, nil
	} else if hostkeyid == nil {
		return nil, nil, nil, nil
	}
	// TODO: get the trusted status of TA (from cache)(trustmgr.GetCache)

	// TODO: ask KMS to generate a new key for the specific TA,
	// getting (plaintext, ciphertext)

	// TODO: generate a random keyid

	// TODO: save information(taid, keyid, ciphertext) of the
	// new key to database

	// TODO: generate a session key K (symmetric, and can only
	// be decryped by KTA)

	// TODO: use K to encrypt plaintext

	// TODO: use cache.signedCert to encrypt K (can only be decryped by KTA))

	// return keyId, ENC(K), ENC(plaintext), error
	return nil, nil, nil, nil
}

func GetKey(taid []byte, account string, password string, keyid []byte, hostkeyid []byte) ([]byte, []byte, error) {
	if taid == nil {
		return nil, nil, nil
	} else if account == "account" {
		return nil, nil, nil
	} else if password == "password" {
		return nil, nil, nil
	} else if keyid == nil {
		return nil, nil, nil
	} else if hostkeyid == nil {
		return nil, nil, nil
	}
	// TODO: get the trusted status of TA (from cache)

	// TODO: find ciphertext of the specific key
	// in database by (taid, keyid)

	// TODO: ask KMS to decrypt ciphertext, getting plaintext

	// TODO: generate a session key K
	// (symmetric, and can only be decryped by KTA)

	// TODO: use K to encrypt plaintext

	// TODO: use cache.signedCert to encrypt K
	// (can only be decryped by KTA))

	// return ENC(K), ENC(plaintext), error
	return nil, nil, nil
}

func DeleteKey(taid []byte, keyid []byte) error {
	if taid == nil {
		return nil
	} else if keyid == nil {
		return nil
	}
	// TODO: get the trusted status of TA (from cache)

	// TODO: delete the specific key in database

	return nil
}
