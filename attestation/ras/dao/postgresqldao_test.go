package dao

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/stretchr/testify/assert"
)

var (
	ci = &entity.ClientInfo{
		Info: map[string]string{
			"info name1": "info value1",
			"info name2": "info value2",
		},
	}
	ci1 = entity.ClientInfo{
		Info: map[string]string{
			"client_name":        "test_client",
			"client_type":        "test_type",
			"client_description": "test description",
		},
	}
	pcrInfo = entity.PcrInfo{
		AlgName: "sha256",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}
	biosItem1 = entity.ManifestItem{
		Name:   "test bios name1",
		Value:  "test bios value1",
		Detail: "test bios detail1",
	}
	biosItem2 = entity.ManifestItem{
		Name:   "test bios name2",
		Value:  "test bios value2",
		Detail: "test bios detail2",
	}
	imaItem1 = entity.ManifestItem{
		Name:   "test ima name1",
		Value:  "test ima value1",
		Detail: "test ima detail1",
	}
	biosManifest = entity.Manifest{
		Type: "bios",
		Items: []entity.ManifestItem{
			1: biosItem1,
			2: biosItem2,
		},
	}
	imaManifest = entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			1: imaItem1,
		},
	}
	baseMeasurements = []entity.Measurement{
		0: {
			Type:  "bios",
			Name:  "test bios name1",
			Value: "test bios value1",
		},
		1: {
			Type:  "bios",
			Name:  "test bios name2",
			Value: "test bios value2",
		},
		2: {
			Type:  "ima",
			Name:  "test ima name1",
			Value: "test ima value1",
		},
	}
)

func TestPostgreSqlDAOSaveReport(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

	ic := createRandomCert()
	id, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}

	testReport := &entity.Report{
		PcrInfo: pcrInfo,
		Manifest: []entity.Manifest{
			1: biosManifest,
			2: imaManifest,
		},
		ClientID:   id,
		ClientInfo: ci1,
	}

	psdErr := psd.SaveReport(testReport)
	if psdErr != nil {
		fmt.Println(psdErr)
		t.FailNow()
	}

}

func TestRegisterClient(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

	ic := []byte("test ic3")
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
}

func TestUnRegisterClient(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

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

func TestSaveAndSelectBaseValue(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer psd.Destroy()

	clientIds, err := psd.SelectAllClientIds()
	if err != nil {
		t.Fatal(err)
	}
	testMea := entity.MeasurementInfo{
		ClientID: clientIds[0],
		PcrInfo:  pcrInfo,
		Manifest: baseMeasurements,
	}
	err = psd.SaveBaseValue(clientIds[0], &testMea)
	if err != nil {
		t.Fatal(err)
	}
	mea, err := psd.SelectBaseValueById(clientIds[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("measurement info : %v", mea)
	testCase := []struct {
		input1 string
		input2 string
	}{
		{mea.PcrInfo.AlgName, pcrInfo.AlgName},
		{mea.PcrInfo.Values[1], pcrInfo.Values[1]},
	}
	for i := 0; i < len(testCase); i++ {
		if testCase[i].input1 != testCase[i].input2 {
			t.Errorf("test base value function failed")
		}
	}
}

func TestSelectReportById(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

	ic := createRandomCert()
	id, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}

	testReport := &entity.Report{
		PcrInfo: pcrInfo,
		Manifest: []entity.Manifest{
			1: biosManifest,
			2: imaManifest,
		},
		ClientID:   id,
		ClientInfo: ci1,
	}

	for i := 0; i < 3; i++ {
		psdErr := psd.SaveReport(testReport)
		if psdErr != nil {
			fmt.Println(psdErr)
			t.FailNow()
		}
		time.Sleep(1 * time.Second)
	}
	reports, err := psd.SelectReportsById(id)
	if err != nil {
		t.Fatal(err)
	}
	latestReport, err := psd.SelectLatestReportById(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the latest report is : %v", latestReport)
	for i, r := range reports {
		t.Logf("report %d: %v", i, r)
		if latestReport.ReportTime.Before(r.ReportTime) {
			t.Fatalf("get latest report failed")
		}
	}
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
