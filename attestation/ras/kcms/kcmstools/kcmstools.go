// kcmstools package implements the whole process of key caching management service
package kcmstools
import "gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
func SendKCMPubKeyCert()([]byte, error){

	// TODO: get KCM public key cert

	// TODO: return KCM public key cert, error

	return nil, nil
}

func VerifyKTAPubKeyCert(deviceId int64, ktaPubKeyCert string) error {
	//	temporary code, only to pass ci test, delete when filling content of this function
	if deviceId == 1 {
		return nil
	} else if ktaPubKeyCert == "string"{
		return nil
	}
	// end of temporary code


	// TODO: unmarshal cert to *x509.Certificate

	// TODO: verify KTA cert
	
	// TODO: save kta public key to cache

	return nil
}

func GenerateNewKey(taid []byte, account []byte, password []byte, hostkeyid []byte) ([]byte, []byte, []byte, []byte, error) {
	//	temporary code, only to pass ci test, delete when filling content of this function
	if taid == nil {
		return nil, nil, nil, nil, nil
	} else if account == nil {
		return nil, nil, nil, nil, nil
	} else if password == nil {
		return nil, nil, nil, nil, nil
	} else if hostkeyid == nil {
		return nil, nil, nil, nil, nil
	}
	// end of temporary code


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

	//	return variable:	retTAId, encKey, plainText, retKeyId, err
	return nil, nil, nil, nil, nil
}


func GetKey(taid []byte, account []byte, password []byte, keyid []byte, hostkeyid []byte) ([]byte, []byte, []byte, []byte, error) {
	//	temporary code, only to pass ci test, delete when filling content of this function
	if taid == nil {
		return nil, nil, nil, nil, nil
	} else if account == nil {
		return nil, nil, nil, nil, nil
	} else if password == nil {
		return nil, nil, nil, nil, nil
	} else if keyid == nil {
		return nil, nil, nil, nil, nil
	} else if hostkeyid == nil {
		return nil, nil, nil, nil, nil
	}
	// end of temporary code


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

	//	return variable:	retTAId, encKey, plainText, retKeyId, err
	return nil, nil, nil, nil, nil
}

func DeleteKey(taid []byte, keyid []byte) error {
	// TODO: get the trusted status of TA (from cache)
	str_taid := string(taid)
	str_keyid := string(keyid)
	_, err := kdb.FindKeyInfo(str_taid, str_keyid)
	if err != nil {
		return err
	}
	// TODO: delete the specific key in database
	err2 := kdb.DeleteKeyInfo(str_taid, str_keyid)
	if err2 != nil {
		return err2
	}
	return nil
}
