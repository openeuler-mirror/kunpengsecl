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
		Values: map[int]string{
			2: pcrVal2,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	bvpcrInfo2 = entity.PcrInfo{
		Values: map[int]string{
			2: pcrVal1,
			5: pcrVal5,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	repopcrInfo = entity.PcrInfo{
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

	bmea = entity.Measurement{
		Type:  mtBIOS,
		Name:  name1,
		Value: value1,
	}

	bmea2 = entity.Measurement{
		Type:  mtBIOS,
		Name:  name2,
		Value: value2,
	}

	imea = entity.Measurement{
		Type:  mtIMA,
		Name:  name1,
		Value: value1,
	}

	imea2 = entity.Measurement{
		Type:  mtIMA,
		Name:  name2,
		Value: value2,
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
	config.GetDefault(config.ConfServer)
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
	config.GetDefault(config.ConfServer)
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
		{testReport2, testMea2, nil},
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
	config.GetDefault(config.ConfServer)
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
		{testReport2, testMea2, nil},
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

func TestBIOSValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	var bv *BIOSVerifier

	const sha256HashAllZero = "0000000000000000000000000000000000000000000000000000000000000000"
	pibv := entity.PcrInfo{
		Values: map[int]string{
			0: sha256HashAllZero,
			1: "8acfdc0d15afa6e5ea69159c080e11ad1c68551c0f64b5b1e738bc3cac30a655",
			2: sha256HashAllZero,
			3: "dead51c4da465379b8a750ef177ebf28130ebfa4e9a5b0a49ee5a1b341e973e6",
			4: sha256HashAllZero,
			5: sha256HashAllZero,
			6: sha256HashAllZero,
			7: sha256HashAllZero,
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	item1 := entity.ManifestItem{
		Name:   "item1",
		Value:  "0000000011111111aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff",
		Detail: "{\"Pcr\":1,\"BType\":1,\"Digest\":{\"Count\":1,\"Item\":[{\"AlgID\":\"0b00\",\"Item\":\"0000000011111111aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff\"}]},\"DataLen\":3,\"Data\":\"nil\"}",
	}
	item2 := entity.ManifestItem{
		Name:   "item2",
		Value:  "0000000022222222aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff",
		Detail: "{\"Pcr\":1,\"BType\":1,\"Digest\":{\"Count\":1,\"Item\":[{\"AlgID\":\"0b00\",\"Item\":\"0000000022222222aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff\"}]},\"DataLen\":3,\"Data\":\"nil\"}",
	}
	item3 := entity.ManifestItem{
		Name:   "item3",
		Value:  "0000000033333333aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff",
		Detail: "{\"Pcr\":3,\"BType\":1,\"Digest\":{\"Count\":1,\"Item\":[{\"AlgID\":\"0b00\",\"Item\":\"0000000033333333aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff\"}]},\"DataLen\":3,\"Data\":\"nil\"}",
	}
	mf := entity.Manifest{
		Type:  "bios",
		Items: []entity.ManifestItem{item1, item2, item3},
	}

	report := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{mf},
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}

	testCase := []struct {
		input  *entity.Report
		result error
	}{
		{report, nil},
		//{report, errcase},
	}
	for i := 0; i < len(testCase); i++ {
		err := bv.Validate(testCase[i].input)
		if err == testCase[i].result {
			t.Logf("test BIOS Validate success at case %d\n", i)
		} else if err.Error() == testCase[i].result.Error() {
			t.Logf("test BIOS Validate success at case %d\n", i)
		} else {
			t.Errorf("test BIOS Validate error at case %d\n", i)
		}
	}
}

func TestBIOSVerify(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	var bv *BIOSVerifier

	baseValue := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{bmea, bmea2, imea, imea2},
	}

	testReport := &entity.Report{
		Manifest: []entity.Manifest{bm}, //i1 i2
	}

	testReport2 := &entity.Report{
		Manifest: []entity.Manifest{bm2}, //i1 i3
	}

	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue, testReport, nil},
		{baseValue, testReport2, fmt.Errorf("bios manifest verification failed")},
	}
	for i := 0; i < len(testCase); i++ {
		err := bv.Verify(testCase[i].input1, testCase[i].input2)
		if err == testCase[i].result || err.Error() == testCase[i].result.Error() {
			t.Logf("test BIOS Verify success at case %d\n", i)
		} else {
			t.Errorf("test BIOS Verify error at case %d\n", i)
		}

	}
}

func TestIMAVerify(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	var iv *IMAVerifier

	baseValue := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{bmea, bmea2, imea, imea2},
	}

	testReport := &entity.Report{
		Manifest: []entity.Manifest{im}, //i1 i2
	}

	testReport2 := &entity.Report{
		Manifest: []entity.Manifest{im2}, //i1 i3
	}

	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue, testReport, nil},
		{baseValue, testReport2, fmt.Errorf("ima manifest verification failed")},
	}
	for i := 0; i < len(testCase); i++ {
		err := iv.Verify(testCase[i].input1, testCase[i].input2)
		if err == testCase[i].result || err.Error() == testCase[i].result.Error() {
			t.Logf("test IMA Verify success at case %d\n", i)
		} else {
			t.Errorf("test IMA Verify error at case %d\n", i)
		}

	}
}

func TestIMAValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()
	var iv *IMAVerifier

	const sha1HashAllZero = "0000000000000000000000000000000000000000"
	pibv := entity.PcrInfo{
		Values: map[int]string{
			0:  sha1HashAllZero,
			1:  "073ee1e91b686efef30ec49f081fe93355de389e",
			2:  sha1HashAllZero,
			3:  "34ac889f14ac927f1198daf306f9da76dde64a9f",
			4:  sha1HashAllZero,
			5:  sha1HashAllZero,
			6:  sha1HashAllZero,
			7:  sha1HashAllZero,
			10: "41bdfa8ecc891b23da8d9be1487b55d828f5ae65",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	item := entity.ManifestItem{
		Name:   "boot_aggregate",
		Value:  "6963796540f9a94a8770f6dea2038d5a1a8b6a21",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"6963796540f9a94a8770f6dea2038d5a1a8b6a21\",\"TemplateName\":\"name1\",\"FiledataHash\":\"0000000000000000000000000000000000000000\",\"FilenameHint\":\"boot_aggregate\"}",
	}
	item2 := entity.ManifestItem{
		Name:   "hint2",
		Value:  "c4b091b099eaaacb9e01295be8a1eb6de21da66e",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"c4b091b099eaaacb9e01295be8a1eb6de21da66e\",\"TemplateName\":\"name2\",\"FiledataHash\":\"0000000000000000000000000000000000000000\",\"FilenameHint\":\"hint2\"}",
	}
	item3 := entity.ManifestItem{
		Name:   "hint3",
		Value:  "d4a5327c1b04a1129220e821331c68c3b3179a9c",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"d4a5327c1b04a1129220e821331c68c3b3179a9c\",\"TemplateName\":\"name3\",\"FiledataHash\":\"0000000000000000000000000000000000000000\",\"FilenameHint\":\"hint3\"}",
	}
	mf := entity.Manifest{
		Type:  mtIMA,
		Items: []entity.ManifestItem{item, item2, item3},
	}

	report := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{mf},
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}

	testCase := []struct {
		input  *entity.Report
		result error
	}{
		{report, nil},
		//{report, errcase},
	}
	for i := 0; i < len(testCase); i++ {
		err := iv.Validate(testCase[i].input)
		if err == testCase[i].result || err.Error() == testCase[i].result.Error() {
			t.Logf("test ima Validate success at case %d\n", i)
		} else {
			t.Errorf("test ima Validate error at case %d\n", i)
		}
	}
}
