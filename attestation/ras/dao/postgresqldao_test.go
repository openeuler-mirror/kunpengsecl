package dao

import (
	"fmt"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/stretchr/testify/assert"
)

func TestPostgreSqlDAOSaveReport(t *testing.T) {
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	pcrInfo := entity.PcrInfo{
		AlgName: "sha256",
		Values: []entity.PcrValue{
			1: {
				Id:    1,
				Value: "pcr value 1",
			},
			2: {
				Id:    2,
				Value: "pcr value 2",
			},
		},
		Quote: []byte("test quote"),
	}

	biosItem1 := entity.ManifestItem{
		Name:   "test bios name1",
		Value:  "test bios value1",
		Detail: "test bios detail1",
	}

	biosItem2 := entity.ManifestItem{
		Name:   "test bios name2",
		Value:  "test bios value2",
		Detail: "test bios detail2",
	}

	imaItem1 := entity.ManifestItem{
		Name:   "test ima name1",
		Value:  "test ima value1",
		Detail: "test ima detail1",
	}

	biosManifest := entity.Manifest{
		Type: "bios",
		Items: []entity.ManifestItem{
			1: biosItem1,
			2: biosItem2,
		},
	}

	imaManifest := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			1: imaItem1,
		},
	}

	testReport := &entity.Report{
		PcrInfo: pcrInfo,
		Manifest: []entity.Manifest{
			1: biosManifest,
			2: imaManifest,
		},
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: map[string]string{
				"client_name":        "test_client",
				"client_type":        "test_type",
				"client_description": "test description",
			},
		},
	}

	psdErr := psd.SaveReport(testReport)
	if psdErr != nil {
		fmt.Println(psdErr)
		t.FailNow()
	}

}

func TestRegisterClient(t *testing.T) {
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	ci := &entity.ClientInfo{
		Info: map[string]string{
			"info name1": "info value1",
			"info name2": "info value2",
		},
	}
	ic := "test ic2"
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
}

func TestUnRegisterClient(t *testing.T) {
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	clientIds, err := psd.SelectAllClientIds()
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	err = psd.UnRegisterClient(clientIds[0])
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	newClientIds, err := psd.SelectAllClientIds()
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	assert.NotEqual(t, clientIds[0], newClientIds[0])
}
