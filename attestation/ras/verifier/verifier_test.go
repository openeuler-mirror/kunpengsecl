package verifier

import (
	"fmt"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

const (
	algSHA1  = "sha1"
	mtBIOS   = "bios"
	mtIMA    = "ima"
	pcrVal1  = "pcr value 1"
	pcrVal2  = "pcr value 2"
	pcrVal3  = "pcr value 3"
	pcrVal4  = "pcr value 4"
	pcrVal5  = "pcr value 5"
	quoteVal = "test quote"
	name1    = "name1"
	value1   = "name1 value"
	detail1  = "name1 detail"
	name2    = "name2"
	value2   = "name2 value"
	detail2  = "name2 detail"
	name3    = "name3"
	value3   = "name3 value"
	detail3  = "name3 detail"
)

var (
	bvpcrInfo1 = entity.PcrInfo{
		AlgName: algSHA1,
		Values: map[int]string{
			2: pcrVal2,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	bvpcrInfo2 = entity.PcrInfo{
		AlgName: algSHA1,
		Values: map[int]string{
			2: pcrVal1,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	repopcrInfo = entity.PcrInfo{
		AlgName: algSHA1,
		Values: map[int]string{
			1: pcrVal1,
			2: pcrVal2,
			3: pcrVal3,
			4: pcrVal4,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	pi  = repopcrInfo
	pi2 = entity.PcrInfo{
		AlgName: algSHA1,
		Values: map[int]string{
			1: pcrVal1,
			4: pcrVal4,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	i1 = entity.ManifestItem{
		Name:   name1,
		Value:  value1,
		Detail: detail1,
	}

	i2 = entity.ManifestItem{
		Name:   name2,
		Value:  value2,
		Detail: detail2,
	}

	i3 = entity.ManifestItem{
		Name:   name3,
		Value:  value3,
		Detail: detail3,
	}

	bm = entity.Manifest{
		Type:  mtBIOS,
		Items: []entity.ManifestItem{i1, i2},
	}
	bm2 = entity.Manifest{
		Type:  mtBIOS,
		Items: []entity.ManifestItem{i1, i3},
	}

	im = entity.Manifest{
		Type:  mtIMA,
		Items: []entity.ManifestItem{i1, i2},
	}

	im2 = entity.Manifest{
		Type:  mtIMA,
		Items: []entity.ManifestItem{i1, i3},
	}
)

func TestPCRVerifierVerify(t *testing.T) {
	var pv *PCRVerifier

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
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()
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
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()

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
	test.CreateServerConfigFile()
	config.GetDefault()
	defer test.RemoveConfigFile()

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
