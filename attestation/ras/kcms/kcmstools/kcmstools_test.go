package kcmstools

import (
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
)

const (
	constDB                = "postgres"
	constDNS               = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"
	constsavekeyinfofailed = "save key information fail %v"
	constfindkeyinfofailed = "find key information fail %v"
)

func TestDeleteKey(t *testing.T) {
	kdb.CreateKdbManager(constDB, constDNS)
	defer kdb.ReleaseKdbManager()
	taid := "1"
	keyid := "testkey1"
	ciphertext := "text1"
	k, err := kdb.SaveKeyInfo(taid, keyid, ciphertext)
	if err != nil {
		t.Logf(constsavekeyinfofailed, err)
	}
	defer kdb.DeleteKeyInfoByID(k.ID)

	_, err1 := kdb.FindKeyInfo(k.TaID, k.KeyID)
	if err1 != nil {
		t.Logf(constfindkeyinfofailed, err1)
	}

	err2 := kdb.DeleteKeyInfo(taid, keyid)
	if err2 == nil {
		t.Logf("delete key information success")
	} else {
		t.Errorf("test DeleteKey failed, error: %v", err2)
	}

}
