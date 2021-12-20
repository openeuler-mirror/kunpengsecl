package dao

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/google/uuid"
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
	config.GetDefault(config.ConfServer)
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
	err = psd.SaveReport(&entity.Report{})
	assert.Error(t, err)

}

func TestRegisterClient(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

	ic := createRandomCert()
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
	_, err2 = psd.RegisterClient(ci, ic)
	assert.Error(t, err2)
}

func TestUnRegisterClient(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	defer psd.Destroy()

	ic := createRandomCert()
	_, err2 := psd.RegisterClient(ci, ic)
	if err2 != nil {
		t.FailNow()
	}
	clientIds, err := psd.SelectAllRegisteredClientIds()
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	err = psd.UnRegisterClient(clientIds[0])
	if err != nil {
		fmt.Println(err)
		t.FailNow()
	}
	assert.NotEqual(t, clientIds[0], 0)
}

func TestSaveAndSelectBaseValue(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer psd.Destroy()

	clientIds, err := psd.SelectAllRegisteredClientIds()
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
	err = psd.SaveBaseValue(-999, &testMea)
	assert.Error(t, err)
	mea, err := psd.SelectBaseValueById(clientIds[0])
	if err != nil {
		t.Fatal(err)
	}
	_, err = psd.SelectBaseValueById(-999)
	assert.Error(t, err)
	t.Logf("measurement info : %v", mea)
	testCase := []struct {
		input1 string
		input2 string
	}{
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
	config.GetDefault(config.ConfServer)
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
	_, err = psd.SelectLatestReportById(-999)
	assert.Error(t, err)

	t.Logf("the latest report is : %v", latestReport)
	for i, r := range reports {
		t.Logf("report %d: %v", i, r)
		if latestReport.ReportTime.Before(r.ReportTime) {
			t.Fatalf("get latest report failed")
		}
	}
}

func TestSelectClientById(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic)
	if err != nil {
		t.FailNow()
	}
	rc, err := psd.SelectClientById(cid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.Equal(t, string(ic), rc.AkCertificate)

	_, err = psd.SelectClientById(-999)
	assert.Error(t, err)
}

func TestSelectClientIds(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	cids := []int64{}
	const registerClientCount = 1
	for i := 0; i <= registerClientCount; i++ {
		ic := createRandomCert()
		cid, err2 := psd.RegisterClient(ci, ic)
		if err2 != nil {
			t.Fatalf("%v", err2)
		}
		cids = append(cids, cid)
	}
	psd.UnRegisterClient(cids[0])
	allCids, err := psd.SelectAllClientIds()
	if err != nil {
		t.Fatalf("%v", err)
	}
	registeredCids, err := psd.SelectAllRegisteredClientIds()
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.Contains(t, allCids, cids[0])
	assert.NotContains(t, registeredCids, cids[0])
}

func TestSelectClientInfobyId(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(&ci1, ic)
	if err != nil {
		t.FailNow()
	}
	result, err := psd.SelectAllClientInfobyId(cid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, err = psd.SelectAllClientInfobyId(-999)
	assert.Error(t, err)

	for k, v := range result {
		assert.Equal(t, v, ci1.Info[k])
	}
	keys := make([]string, 0, len(ci1.Info))
	for k := range ci1.Info {
		keys = append(keys, k)
	}
	result2, err := psd.SelectClientInfobyId(cid, keys[:len(keys)-1])
	if err != nil {
		t.Fatalf("%v", err)
	}
	for k, v := range result2 {
		assert.Equal(t, v, ci1.Info[k])
	}

	_, err = psd.SelectClientInfobyId(-999, keys[:len(keys)-1])
	assert.Error(t, err)
}

func TestUpdateRegisterStatusById(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic)
	if err != nil {
		t.FailNow()
	}

	c1, err := psd.SelectClientById(cid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.False(t, c1.IsDeleted)

	err = psd.UpdateRegisterStatusById(cid, true)
	if err != nil {
		t.Fatalf("%v", err)
	}

	c2, err := psd.SelectClientById(cid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.True(t, c2.IsDeleted)

	err = psd.UpdateRegisterStatusById(cid, false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	c3, err := psd.SelectClientById(cid)
	if err != nil {
		t.Fatalf("%v", err)
	}
	assert.False(t, c3.IsDeleted)
}

func TestUpdateRegisterClient(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic)
	assert.NoError(t, err)

	time2 := time.Now()
	ic2 := createRandomCert()
	c2 := entity.RegisterClient{
		ClientID:      cid,
		RegisterTime:  time2,
		AkCertificate: string(ic2),
		IsOnline:      false,
		IsDeleted:     true,
	}
	err = psd.UpdateRegisterClient(&c2)
	assert.NoError(t, err)
	result, err := psd.SelectClientById(cid)
	assert.NoError(t, err)
	assert.Equal(t, time2.Format("2006/01/02 15:04:05"), result.RegisterTime.Format("2006/01/02 15:04:05"))
	assert.Equal(t, string(ic2), result.AkCertificate)
	assert.Equal(t, false, result.IsOnline)
	assert.Equal(t, true, result.IsDeleted)
}
func TestInsertAndSelectContainer(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic)
	if err != nil {
		t.FailNow()
	}

	uuid := uuid.New().String()
	testCon1 := entity.Container{
		UUID:     uuid,
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	}
	testCbv1 := entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         ci.Info,
	}
	err = psd.InsertContainer(&testCon1)
	assert.NoError(t, err)
	err = psd.InsertContainer(&entity.Container{})
	assert.Error(t, err)

	result1, err := psd.SelectContainerByUUId(uuid)
	assert.NoError(t, err)
	assert.Equal(t, cid, result1.ClientId)

	_, err = psd.SelectContainerByUUId("a")
	assert.Error(t, err)

	err = psd.InsertContainerBaseValue(&testCbv1)
	assert.NoError(t, err)

	result2, err := psd.SelectContainerBaseValueByUUId(uuid)
	assert.NoError(t, err)
	assert.Equal(t, len(ci.Info), len(result2.Value))
	_, err = psd.SelectContainerBaseValueByUUId("a")
	assert.Error(t, err)
}

func TestInsertAndSelectDevice(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	psd, err := CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()

	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic)
	if err != nil {
		t.FailNow()
	}

	rand.Seed(time.Now().Unix())
	deviceId := rand.Int31()
	testP1 := entity.PcieDevice{
		ID:       int64(deviceId),
		ClientId: cid,
		Online:   true,
		Deleted:  false,
	}
	testPbv1 := entity.PcieBaseValue{
		DeviceID: int64(deviceId),
		Value:    ci.Info,
	}
	err = psd.InsertDevice(&testP1)
	assert.NoError(t, err)
	err = psd.InsertDevice(&entity.PcieDevice{})
	assert.Error(t, err)

	result1, err := psd.SelectDeviceById(int64(deviceId))
	assert.NoError(t, err)
	assert.Equal(t, cid, result1.ClientId)

	_, err = psd.SelectDeviceById(-999)
	assert.Error(t, err)

	err = psd.InsertDeviceBaseValue(&testPbv1)
	assert.NoError(t, err)
	result2, err := psd.SelectDeviceBaseValueById(int64(deviceId))
	assert.NoError(t, err)
	assert.Equal(t, len(ci.Info), len(result2.Value))
	_, err = psd.SelectDeviceBaseValueById(-999)
	assert.Error(t, err)
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
