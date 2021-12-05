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

var (
	pcrInfo = entity.PcrInfo{
		AlgName: "sha1",
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
