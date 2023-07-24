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

// kdb package implements the access to the database in kcms.
package kdb

import (
	"database/sql"

	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	_ "github.com/lib/pq"
)

const (
	sqlFindKeyInfo          = `SELECT id, taid, keyid, ciphertext FROM keyinfo WHERE taid=$1 AND keyid=$2`
	sqlDeleteKeyInfoByID    = `DELETE FROM keyinfo WHERE id=$1`
	sqlDeleteKeyInfo        = `DELETE FROM keyinfo WHERE taid=$1 AND keyid=$2`
	sqlInsertKeyInfo        = `INSERT INTO keyinfo(taid, keyid, ciphertext) VALUES ($1, $2, $3) RETURNING id`
	sqlFindPubKeyInfo       = `SELECT id, deviceid, pubkeycert FROM pubkeyinfo WHERE deviceid=$1`
	sqlDeletePubKeyInfoByID = `DELETE FROM pubkeyinfo WHERE id=$1`
	sqlDeletePubKeyInfo     = `DELETE FROM pubkeyinfo WHERE deviceid=$1`
	sqlInsertPubKeyInfo     = `INSERT INTO pubkeyinfo(deviceid, pubkeycert) VALUES ($1, $2) RETURNING id`
)

type (
	// required struct
	// KdbManager handles all key information in key database.
	KdbManager struct {
		// save key information and support
		// rest api search operations...
		db *sql.DB
	}
)

var (
	kmgr *KdbManager = nil
)

// CreateKdbManager creates a new kdb manager
// and a database connection poll to enhance performance.
func CreateKdbManager(dbType, dbConfig string) {
	var err error
	if kmgr != nil {
		return
	}
	kmgr = &KdbManager{}
	kmgr.db, err = sql.Open(dbType, dbConfig)
	if err != nil {
		kmgr = nil
		return
	}
}

// ReleaseKdbManager releases the manager database connection.
func ReleaseKdbManager() {
	if kmgr == nil {
		return
	}
	if kmgr.db != nil {
		kmgr.db.Close()
		kmgr.db = nil
	}
	kmgr = nil
}

// FindKeyInfo returns the keyinfo by taid and keyid.
func FindKeyInfo(taid, keyid string) (*typdefs.KeyinfoRow, error) {
	if kmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	keyinfo := &typdefs.KeyinfoRow{}
	err := kmgr.db.QueryRow(sqlFindKeyInfo, taid, keyid).
		Scan(&keyinfo.ID, &keyinfo.TaID, &keyinfo.KeyID, &keyinfo.Ciphertext)
	if err != nil {
		return nil, err
	}
	return keyinfo, nil
}

// DeleteKeyInfoByID deletes a specific keyinfo by keyinfo id.
func DeleteKeyInfoByID(id int64) error {
	if kmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := kmgr.db.Exec(sqlDeleteKeyInfoByID, id)
	if err != nil {
		return err
	}
	return nil
}

// DeleteKeyInfo deletes a specific keyinfo by taid and keyid.
func DeleteKeyInfo(taid, keyid string) error {
	if kmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := kmgr.db.Exec(sqlDeleteKeyInfo, taid, keyid)
	if err != nil {
		return err
	}
	return nil
}

// SaveKeyInfo insert a new keyinfo to database, including taid, keyid, cipherkey.
func SaveKeyInfo(taid, keyid, cipherkey string) (*typdefs.KeyinfoRow, error) {
	if kmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	k := typdefs.KeyinfoRow{TaID: taid, KeyID: keyid, Ciphertext: cipherkey}
	err := kmgr.db.QueryRow(sqlInsertKeyInfo, k.TaID, k.KeyID, k.Ciphertext).Scan(&k.ID)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// FindPubKeyInfo returns the pubkeyinfo by deviceid.
func FindPubKeyInfo(deviceid int64) (*typdefs.PubKeyinfoRow, error) {
	if kmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	pubkeyinfo := &typdefs.PubKeyinfoRow{}
	err := kmgr.db.QueryRow(sqlFindPubKeyInfo, deviceid).Scan(&pubkeyinfo.ID, &pubkeyinfo.DeviceID, &pubkeyinfo.PubKeyCert)
	if err != nil {
		return nil, err
	}
	return pubkeyinfo, nil
}

// DeletePubKeyInfoByID deletes a specific pubkeyinfo by pubkeyinfo id.
func DeletePubKeyInfoByID(id int64) error {
	if kmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := kmgr.db.Exec(sqlDeletePubKeyInfoByID, id)
	if err != nil {
		return err
	}
	return nil
}

// DeletePubKeyInfo deletes a specific keyinfo by deviceid.
func DeletePubKeyInfo(deviceid int64) error {
	if kmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := kmgr.db.Exec(sqlDeletePubKeyInfo, deviceid)
	if err != nil {
		return err
	}
	return nil
}

// SavePubKeyInfo insert a new keyinfo to database, including deviceid, pubkey.
func SavePubKeyInfo(deviceid int64, pubkeycert string) (*typdefs.PubKeyinfoRow, error) {
	if kmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	k := typdefs.PubKeyinfoRow{DeviceID: deviceid, PubKeyCert: pubkeycert}
	err := kmgr.db.QueryRow(sqlInsertPubKeyInfo, k.DeviceID, k.PubKeyCert).Scan(&k.ID)
	if err != nil {
		return nil, err
	}
	return &k, nil
}
