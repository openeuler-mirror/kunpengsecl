package kdb

import (
	"testing"
)

const (
	constDB                = "postgres"
	constDNS               = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"
	constsavekeyinfofailed = "save key information fail %v"
)

func TestSaveKeyInfo(t *testing.T) {
	keyinfos := []struct {
		TaID       string
		KeyID      string
		Ciphertext string
	}{
		{"1", "testkey1", "text1"},
		{"2", "testkey2", "text2"},
		{"3", "testkey3", "text3"},
		{"4", "testkey4", "text4"},
		{"5", "testkey5", "text5"},
		{"6", "testkey6", "text6"},
	}
	CreateKdbManager(constDB, constDNS)
	defer ReleaseKdbManager()
	for _, k := range keyinfos {
		SaveKeyInfo(k.TaID, k.KeyID, k.Ciphertext)
		krow, err := FindKeyInfo(k.TaID, k.KeyID)
		t.Logf(krow.Ciphertext)
		if err != nil {
			t.Errorf("test FindKeyInfo failed, err: %s", err)
		}
		defer DeleteKeyInfoByID(krow.ID)
	}
}

func TestFindKeyInfo(t *testing.T) {
	CreateKdbManager(constDB, constDNS)
	defer ReleaseKdbManager()
	taid := "1"
	keyid := "testkey1"
	ciphertext := "text1"
	k, err := SaveKeyInfo(taid, keyid, ciphertext)
	if err != nil {
		t.Logf(constsavekeyinfofailed, err)
	}
	defer DeleteKeyInfoByID(k.ID)

	k1, err := FindKeyInfo(k.TaID, k.KeyID)
	if err == nil {
		t.Logf("find key information by taid=%s and keyid=%s, key=%v\n", k1.TaID, k1.KeyID, k)
	} else {
		t.Errorf("find by taid and keyid error: %v", err)
	}
}
