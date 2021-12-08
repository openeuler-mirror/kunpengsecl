package trustmgr

import (
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/stretchr/testify/assert"
)

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}

type testExtractor struct {
}

func (tv *testExtractor) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	mInfo.ClientID = report.ClientID
	mInfo.PcrInfo = report.PcrInfo
	for _, mf := range report.Manifest {
		for _, mi := range mf.Items {
			mInfo.Manifest = append(mInfo.Manifest, entity.Measurement{
				Type:  mf.Type,
				Name:  mi.Name,
				Value: mi.Value,
			})
		}
	}
	return nil
}

var (
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
			0: biosItem1,
			1: biosItem2,
		},
	}

	imaManifest = entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			0: imaItem1,
		},
	}

	clientInfo = entity.ClientInfo{
		Info: map[string]string{
			"client_name":        "test_client",
			"client_type":        "test_type",
			"client_description": "test description",
		},
	}
)

func TestRecordReport(t *testing.T) {
	test.CreateServerConfigFile()
	defer test.RemoveConfigFile()
	vm := new(testValidator)
	SetValidator(vm)
	ex := new(testExtractor)
	SetExtractor(ex)
	cfg := config.GetDefault(config.ConfServer)
	ic := createRandomCert()

	clientID, err := RegisterClient(&clientInfo, ic)
	assert.NoError(t, err)

	testReport := &entity.Report{
		PcrInfo: pcrInfo,
		Manifest: []entity.Manifest{
			0: biosManifest,
			1: imaManifest,
		},
		ClientID:   clientID,
		ClientInfo: clientInfo,
	}

	err = RecordReport(testReport)
	assert.NoError(t, err)

	client, err := GetRegisterClientById(clientID)
	assert.NoError(t, err)
	testBeginBVVer := client.BaseValueVer

	// test auto-update
	cfg.SetMgrStrategy(config.RasAutoUpdateStrategy)
	// test all update
	cfg.SetAutoUpdateConfig(entity.AutoUpdateConfig{IsAllUpdate: true})
	err = RecordReport(testReport)
	assert.NoError(t, err)
	client, err = GetRegisterClientById(clientID)
	assert.NoError(t, err)
	assert.Equal(t, testBeginBVVer, client.BaseValueVer)

	testReport.Manifest[0].Items[0].Value = "test changed value 1"
	err = RecordReport(testReport)
	assert.NoError(t, err)
	client, err = GetRegisterClientById(clientID)
	assert.NoError(t, err)
	assert.Equal(t, testBeginBVVer+1, client.BaseValueVer)
	testBeginBVVer++
	// test not all update
	cfg.SetAutoUpdateConfig(entity.AutoUpdateConfig{
		IsAllUpdate:   false,
		UpdateClients: []int64{clientID},
	})
	err = RecordReport(testReport)
	assert.NoError(t, err)
	client, err = GetRegisterClientById(clientID)
	assert.NoError(t, err)
	assert.Equal(t, testBeginBVVer, client.BaseValueVer)

	testReport.Manifest[0].Items[0].Value = "test changed value 2"
	err = RecordReport(testReport)
	assert.NoError(t, err)
	client, err = GetRegisterClientById(clientID)
	assert.NoError(t, err)
	assert.Equal(t, testBeginBVVer+1, client.BaseValueVer)
	testBeginBVVer++

	// test client is not in the list
	cfg.SetAutoUpdateConfig(entity.AutoUpdateConfig{
		IsAllUpdate:   false,
		UpdateClients: []int64{clientID + 10},
	})
	err = RecordReport(testReport)
	assert.NoError(t, err)
	client, err = GetRegisterClientById(clientID)
	assert.NoError(t, err)
	assert.Equal(t, testBeginBVVer, client.BaseValueVer)
}

func TestIsMeasurementUpdate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	mea1 := entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  pcrInfo,
		Manifest: []entity.Measurement{
			0: {
				Type:  "bios",
				Name:  "bios name1",
				Value: "bios value1",
			},
			1: {
				Type:  "ima",
				Name:  "ima name1",
				Value: "ima value1",
			},
		},
	}
	mea2 := entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  pcrInfo,
		Manifest: []entity.Measurement{
			0: {
				Type:  "bios",
				Name:  "bios name1",
				Value: "bios value1",
			},
			1: {
				Type:  "ima",
				Name:  "ima name1",
				Value: "ima value1",
			},
		},
	}
	result := isMeasurementUpdate(&mea1, &mea2)
	assert.False(t, result)

	mea2.Manifest[0].Type = "ima"
	result = isMeasurementUpdate(&mea1, &mea2)
	assert.True(t, result)
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
