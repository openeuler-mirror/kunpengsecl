/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-04-01
Description: Provide database support
*/

package database

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"
)

const (
	sqlRegisterClientByDC = `UPDATE device_key set registered=$1 register_time=$2 client_info=$3 WHERE device_cert=$4`
	sqlFindRegStatusByID  = `SELECT registered FROM device_key WHERE id=$1`
	sqlFindDeviceByDC     = `SELECT registered FROM device_key WHERE device_cert=$1`
	sqlStoreDeviceCert    = `INSERT INTO device_key(device_cert, registered, trusted, client_info) VALUES ($1, $2, $3, $4) RETURNING id`
	sqlFindAKCertByAC     = `SELECT id FROM akey_cert WHERE ak_certificate=$1`
	sqlStoreAKeyCert      = `INSERT INTO akey_cert(ak_certificate, device_id, create_time, expire_time, available) VALUES ($1, $2, $3, $4, $5) RETURNING id`
	sqlUpdateAvailable    = `UPDATE akey_cert set available=false WHERE device_id=$1`
)

type (
	// DKeyRow stores one record of device key information
	// in database table `device_key`.
	DKeyRow struct {
		Id          int64
		Device_cert string
		Registered  bool
		Trusted     bool
		Reg_time    time.Time
		Client_info string
	}
	// AKCertRow stores one record of ak cert key information
	// in database table `akey_cert`.
	AKCertRow struct {
		Id        int64
		Device_id int64
		Cre_time  time.Time
		Exp_time  time.Time
		Akey_cert string
		Available bool
	}
)

var (
	db *sql.DB
)

// CreateDB opens sql service according to dname and dsname.
func CreateDB(dname, dsname string) (*sql.DB, error) {
	if db != nil {
		return db, nil
	}
	db, err := sql.Open(dname, dsname)
	if err != nil {
		return nil, errors.New("open database failed")
	}
	return db, nil
}

// InsertDKeyRow inserts device key row in table `device_key`.
func InsertDKeyRow(dkcert []byte) (DKeyRow, error) {
	var d DKeyRow = DKeyRow{
		Device_cert: string(dkcert),
	}
	err := db.QueryRow(sqlFindDeviceByDC, d.Device_cert).Scan(&d.Id)
	if err == nil {
		return DKeyRow{}, errors.New("device already exist")
	}
	d = DKeyRow{
		Registered:  false,
		Trusted:     true,
		Client_info: "",
	}
	err = db.QueryRow(sqlStoreDeviceCert,
		d.Device_cert, d.Registered, d.Trusted, d.Client_info).Scan(&d.Id)
	if err != nil {
		return DKeyRow{}, err
	}
	return d, nil
}

// InsertAKCertRow inserts ak cert row in table `akey_cert`.
func InsertAKCertRow(akcert []byte, did int64) error {
	var a AKCertRow = AKCertRow{
		Akey_cert: string(akcert),
		Device_id: did,
	}
	err := db.QueryRow(sqlFindAKCertByAC, a.Akey_cert).Scan(&a.Id) // maybe it is unneccessary
	if err == nil {
		return errors.New("akcert already exist")
	}
	acBlock, _ := pem.Decode(akcert)
	ac, err := x509.ParseCertificate(acBlock.Bytes)
	if err != nil {
		return err
	}
	a = AKCertRow{
		Cre_time:  ac.NotBefore,
		Exp_time:  ac.NotAfter,
		Available: true,
	}
	err = SetAllAKCertUnavailable(did) // ?
	if err != nil {
		return err
	}
	err = db.QueryRow(sqlStoreAKeyCert, a.Akey_cert, a.Device_id, a.Cre_time, a.Exp_time, a.Available).Scan(&a.Id)
	if err != nil {
		return err
	}
	return nil
}

// SetAllAKCertUnavailable sets available=false in table `akey_cert` according to device id.
func SetAllAKCertUnavailable(did int64) error {
	_, err := db.Exec(sqlUpdateAvailable, did)
	if err != nil {
		return err
	}
	return nil
}
