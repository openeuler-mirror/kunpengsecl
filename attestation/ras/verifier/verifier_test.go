package verifier

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
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
  mgrstrategy: auto
  basevalue-extract-rules:
    pcrinfo:
      pcrselection: [1, 2, 3, 4]
    manifest:
      -
        type: bios
        name: ["name1", "name2"]
      -
        type: ima
        name: ["name1", "name2"] 
  `

func createConfigFile() {
	ioutil.WriteFile("./config.yaml", []byte(testConfig), 0644)
}

func TestPCRVerifier_Verify(t *testing.T) {
	var pv *PCRVerifier

	bvpcrInfo1 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			2: "pcr value 2",
			5: "pcr value 5",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}

	bvpcrInfo2 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			2: "pcr value 1",
			5: "pcr value 5",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}

	repopcrInfo := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
			3: "pcr value 3",
			4: "pcr value 4",
			5: "pcr value 5",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}

	baseValue1 := &entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  bvpcrInfo1,
		Manifest: nil,
	}

	baseValue2 := &entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  bvpcrInfo2,
		Manifest: nil,
	}

	report := &entity.Report{
		PcrInfo:  repopcrInfo,
		Manifest: nil,
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}

	errcase := fmt.Errorf("PCR verification failed")
	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue1, report, nil},
		{baseValue2, report, errcase},
	}
	for i := 0; i < len(testCase); i++ {
		err := pv.Verify(testCase[i].input1, testCase[i].input2)
		if err == testCase[i].result {
			t.Logf("test PCR Verify success at case %d\n", i)
		} else if err.Error() == testCase[i].result.Error() {
			t.Logf("test PCR Verify success at case %d\n", i)
		} else {
			t.Errorf("test PCR Verify error at case %d\n", i)
		}
	}
}

func TestPCRExtract(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
	pi := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
			3: "pcr value 3",
			4: "pcr value 4",
			5: "pcr value 5",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}
	pi2 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			1: "pcr value 1",
			4: "pcr value 4",
			5: "pcr value 5",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte("test quote"),
		},
	}
	testReport := &entity.Report{
		PcrInfo: pi,
	}
	testReport2 := &entity.Report{
		PcrInfo: pi2,
	}
	testMea := &entity.MeasurementInfo{}
	testMea2 := &entity.MeasurementInfo{}
	testCase := []struct {
		input1 *entity.Report
		input2 *entity.MeasurementInfo
		result error
	}{
		{testReport, testMea, nil},
		{testReport2, testMea2, fmt.Errorf("extract failed. pcr number %v doesn't exist in this report", 2)},
	}

	pv := new(PCRVerifier)
	for _, tc := range testCase {
		err := pv.Extract(tc.input1, tc.input2)
		if err != nil {
			if err.Error() != tc.result.Error() {
				t.Error(err)
			}
		} else {
			if tc.result != nil {
				t.Error("pcr extract test failed")
			}
		}
	}
	t.Log(testMea)
}

func TestBIOSExtract(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
	bm := entity.Manifest{
		Type: "bios",
		Items: []entity.ManifestItem{
			{
				Name:   "name1",
				Value:  "name1 value",
				Detail: "name1 detail",
			},
			{
				Name:   "name2",
				Value:  "name2 value",
				Detail: "name2 detail",
			},
		},
	}
	bm2 := entity.Manifest{
		Type: "bios",
		Items: []entity.ManifestItem{
			{
				Name:   "name1",
				Value:  "name1 value",
				Detail: "name1 detail",
			},
			{
				Name:   "name3",
				Value:  "name3 value",
				Detail: "name3 detail",
			},
		},
	}
	testReport := &entity.Report{
		Manifest: []entity.Manifest{bm},
	}
	testReport2 := &entity.Report{
		Manifest: []entity.Manifest{bm2},
	}
	testMea := &entity.MeasurementInfo{}
	testMea2 := &entity.MeasurementInfo{}
	testCase := []struct {
		input1 *entity.Report
		input2 *entity.MeasurementInfo
		result error
	}{
		{testReport, testMea, nil},
		{testReport2, testMea2, fmt.Errorf("extract failed. bios manifest name %v doesn't exist in this report", "name2")},
	}

	bv := new(BIOSVerifier)
	for _, tc := range testCase {
		err := bv.Extract(tc.input1, tc.input2)
		if err != nil {
			if err.Error() != tc.result.Error() {
				t.Error(err)
			}
		} else {
			if tc.result != nil {
				t.Error("bios extract test failed")
			}
		}
	}
	t.Log(testMea)
}

func TestIMAExtract(t *testing.T) {
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
	im := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			{
				Name:   "name1",
				Value:  "name1 value",
				Detail: "name1 detail",
			},
			{
				Name:   "name2",
				Value:  "name2 value",
				Detail: "name2 detail",
			},
		},
	}
	im2 := entity.Manifest{
		Type: "ima",
		Items: []entity.ManifestItem{
			{
				Name:   "name1",
				Value:  "name1 value",
				Detail: "name1 detail",
			},
			{
				Name:   "name3",
				Value:  "name3 value",
				Detail: "name3 detail",
			},
		},
	}
	testReport := &entity.Report{
		Manifest: []entity.Manifest{im},
	}
	testReport2 := &entity.Report{
		Manifest: []entity.Manifest{im2},
	}
	testMea := &entity.MeasurementInfo{}
	testMea2 := &entity.MeasurementInfo{}
	testCase := []struct {
		input1 *entity.Report
		input2 *entity.MeasurementInfo
		result error
	}{
		{testReport, testMea, nil},
		{testReport2, testMea2, fmt.Errorf("extract failed. ima manifest name %v doesn't exist in this report", "name2")},
	}

	iv := new(IMAVerifier)
	for _, tc := range testCase {
		err := iv.Extract(tc.input1, tc.input2)
		if err != nil {
			if err.Error() != tc.result.Error() {
				t.Error(err)
			}
		} else {
			if tc.result != nil {
				t.Error("bios extract test failed")
			}
		}
	}
	t.Log(testMea)
}
