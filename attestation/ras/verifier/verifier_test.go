package verifier

import (
	"fmt"
	"io/ioutil"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

const testConfig = `database:
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
		Quote: []byte("test quote"),
	}

	bvpcrInfo2 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			2: "pcr value 1",
			5: "pcr value 5",
		},
		Quote: []byte("test quote"),
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
		Quote: []byte("test quote"),
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
	pi := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
			3: "pcr value 3",
			4: "pcr value 4",
			5: "pcr value 5",
		},
		Quote: []byte("test quote"),
	}
	testReport := &entity.Report{
		PcrInfo: pi,
	}
	testMea := &entity.MeasurementInfo{}
	testCase := []struct {
		input1 *entity.Report
		input2 *entity.MeasurementInfo
		result error
	}{
		{testReport, testMea, nil},
	}

	pv := new(PCRVerifier)
	for _, tc := range testCase {
		err := pv.Extract(tc.input1, tc.input2)
		if err != tc.result {
			t.Error(err)
		}
		t.Log(tc.input2.PcrInfo)
	}
}
