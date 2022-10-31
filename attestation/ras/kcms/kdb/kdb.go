// kdb package implements the access to the database in kcm.
package kdb

import (
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
)

func FindKey(taid string, keyid string) (*typdefs.KeyinfoRow, error) {
	// TODO
	return nil, nil
}

func DeleteKey(taid string, keyid string) (*typdefs.KeyinfoRow, error) {
	// TODO
	return nil, nil
}

func SaveKey(taid string, keyid string, cipherkey []byte) error {
	// TODO
	// cipherkey是pem格式，需要把加密后的blob转成可读可见的pem格式
	return nil
}
