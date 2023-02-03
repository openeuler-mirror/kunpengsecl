/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wanghaijing
Create: 2022-11-05
Description: database package for kcms.
*/

package kdb

import (
	"testing"
)

const (
	constDB                   = "postgres"
	constDNS                  = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"
	constsavekeyinfofailed    = "save key information fail %v"
	constsavepubkeyinfofailed = "save pubkey information fail %v"
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

func TestSavePubKeyInfo(t *testing.T) {
	pubkeyinfos := []struct {
		DeviceID   int64
		PubKeyCert string
	}{
		{1, "testpubkey1"},
		{2, "testpubkey2"},
		{3, "testpubkey3"},
		{4, "testpubkey4"},
		{5, "testpubkey5"},
		{6, "testpubkey6"},
	}
	CreateKdbManager(constDB, constDNS)
	defer ReleaseKdbManager()
	for _, k := range pubkeyinfos {
		SavePubKeyInfo(k.DeviceID, k.PubKeyCert)
		krow, err := FindPubKeyInfo(k.DeviceID)
		t.Logf(krow.PubKeyCert)
		if err != nil {
			t.Errorf("test FindPubKeyInfo failed, err: %s", err)
		}
		defer DeletePubKeyInfoByID(krow.ID)
	}
}

func TestFindPubKeyInfo(t *testing.T) {
	CreateKdbManager(constDB, constDNS)
	defer ReleaseKdbManager()
	var deviceid int64 = 1
	pubkeycert := "testpubkey1"
	k, err := SavePubKeyInfo(deviceid, pubkeycert)
	if err != nil {
		t.Logf(constsavepubkeyinfofailed, err)
	}
	defer DeletePubKeyInfoByID(k.ID)

	k1, err := FindPubKeyInfo(k.DeviceID)
	if err == nil {
		t.Logf("find public key information by deviceid=%d, public key=%v\n", k1.DeviceID, k)
	} else {
		t.Errorf("find by deviceid error: %v", err)
	}
}
