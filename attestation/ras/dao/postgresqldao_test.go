package dao

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/stretchr/testify/assert"
)

const testConfig = `conftype: server
database:
  dbname: kunpengsecl
  host: localhost
  password: "postgres"
  port: 5432
  user: "postgres"
racconfig:
  hbduration: 3s
  trustduration: 2m0s
rasconfig:
  changetime: 2021-09-30T11:53:24.0581136+08:00
  mgrstrategy: auto`

func createConfigFile() {
	ioutil.WriteFile("./config.yaml", []byte(testConfig), 0644)
}
func TestPostgreSqlDAOSaveReport(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
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
	ic := createRandomCert()
	id, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
	pcrInfo := entity.PcrInfo{
		AlgName: "sha256",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
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
		ClientID: id,
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
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
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
	ic := []byte("test ic3")
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
}

func TestUnRegisterClient(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
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
	ic := []byte("test ic 1")
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
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
	/*	newClientIds, err := psd.SelectAllClientIds()
		if err != nil {
			fmt.Println(err)
			t.FailNow()
		}
		assert.NotEqual(t, clientIds[0], newClientIds[0])
	*/
	assert.NotEqual(t, clientIds[0], 0)
}

func TestSaveBaseValue(t *testing.T) {
	pcrInfo := entity.PcrInfo{
		AlgName: "sha256",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
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
			0: biosItem1,
			1: biosItem2,
		},
	}
	imaManifest := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: imaItem1,
		},
	}
	manifest := []entity.Manifest{
		0: biosManifest,
		1: imaManifest,
	}

	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
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
	err = psd.SaveBaseValue(clientIds[0], pcrInfo, manifest)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}
}

func TestSelectReportById(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
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
	ic := createRandomCert()
	id, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
	pcrInfo := entity.PcrInfo{
		AlgName: "sha256",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
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
		ClientID: id,
		ClientInfo: entity.ClientInfo{
			Info: map[string]string{
				"client_name":        "test_client",
				"client_type":        "test_type",
				"client_description": "test description",
			},
		},
	}

	for i := 0; i < 3; i++ {
		psdErr := psd.SaveReport(testReport)
		if psdErr != nil {
			fmt.Println(psdErr)
			t.FailNow()
		}
	}
	reports, err := psd.SelectReportById(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(reports)
}

func createRandomCert() []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	strBytes := []byte(str)
	randomCert := []byte{}
	ra := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 6; i++ {
		randomCert = append(randomCert, strBytes[ra.Intn(len(strBytes))])
	}
	return randomCert
}
