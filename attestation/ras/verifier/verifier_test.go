package verifier

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/dao"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

const (
	algSHA1           = "sha1"
	mtBIOS            = "bios"
	mtIMA             = "ima"
	pcrVal1           = "pcr value 1"
	pcrVal2           = "pcr value 2"
	pcrVal3           = "pcr value 3"
	pcrVal4           = "pcr value 4"
	pcrVal5           = "pcr value 5"
	quoteVal          = "test quote"
	name1             = "name1"
	value1            = "name1 value"
	detail1           = "name1 detail"
	name2             = "name2"
	value2            = "name2 value"
	detail2           = "name2 detail"
	name3             = "name3"
	value3            = "name3 value"
	detail3           = "name3 detail"
	sha1HashAllZero   = "0000000000000000000000000000000000000000"
	sha1HashAllFF     = "ffffffffffffffffffffffffffffffffffffffff"
	sha256HashAllZero = "0000000000000000000000000000000000000000000000000000000000000000"
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

func TestPCRVerify(t *testing.T) {
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

	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue1, report, nil},
		{baseValue2, report, fmt.Errorf("PCR verification failed")},
		{nil, nil, fmt.Errorf("invalid input")},
	}
	for i := 0; i < len(testCase); i++ {
		err := pv.Verify(testCase[i].input1, testCase[i].input2)
		res := testCase[i].result
		if err == testCase[i].result || (res != nil && err.Error() == res.Error()) {
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
		{testReport2, testMea2, errors.New("extract failed. bios manifest name name2 doesn't exist in this report")},
	}

	bv := new(BIOSVerifier)
	for _, tc := range testCase {
		err := bv.Extract(tc.input1, tc.input2)
		if err != nil && tc.result != nil {
			if err.Error() != tc.result.Error() {
				t.Error(err)
			}
		} else {
			if err != tc.result {
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
		{testReport2, testMea2, errors.New("extract failed. ima manifest name name2 doesn't exist in this report")},
	}

	iv := new(IMAVerifier)
	for _, tc := range testCase {
		err := iv.Extract(tc.input1, tc.input2)
		if err != nil && tc.result != nil {
			if err.Error() != tc.result.Error() {
				t.Error(err)
			}
		} else {
			if err != tc.result {
				t.Error("bios extract test failed")
			}
		}
	}
	t.Log(testMea)
}

func TestBIOSValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha256AlgStr)
	defer test.RemoveConfigFile()
	var bv *BIOSVerifier

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

	testreport1 := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{mf},
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}
	testreport2 := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{},
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
		{testreport1, nil},
		{testreport2, fmt.Errorf("no bios manifest in report")},
	}
	for i := 0; i < len(testCase); i++ {
		err := bv.Validate(testCase[i].input)
		res := testCase[i].result
		if err == testCase[i].result || (res != nil && err.Error() == res.Error()) {
			t.Logf("test BIOS Validate success at case %d\n", i)
		} else {
			t.Errorf("test BIOS Validate error at case %d\n", i)
		}
	}
}

func TestBIOSVerify(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	var bv *BIOSVerifier

	baseValue := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{bmea, bmea2, imea, imea2},
	}

	baseValue2 := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{},
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
		{baseValue, testReport2, fmt.Errorf("manifest extraction failed")},
		{baseValue2, testReport, nil},
	}
	for i := 0; i < len(testCase); i++ {
		err := bv.Verify(testCase[i].input1, testCase[i].input2)
		res := testCase[i].result
		if err == res || (res != nil && err != nil && err.Error() == res.Error()) {
			t.Logf("test BIOS Verify success at case %d\n", i)
		} else {
			t.Errorf("test BIOS Verify error at case %d: %v\n", i, err)
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

	baseValue2 := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{},
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
		{baseValue, testReport2, fmt.Errorf("manifest extraction failed")},
		{baseValue2, testReport, nil},
	}
	for i := 0; i < len(testCase); i++ {
		err := iv.Verify(testCase[i].input1, testCase[i].input2)
		res := testCase[i].result
		if err == res || (res != nil && err != nil && err.Error() == res.Error()) {
			t.Logf("test IMA Verify success at case %d\n", i)
		} else {
			t.Errorf("test IMA Verify error at case %d: %v\n", i, err)
		}

	}
}

func TestIMAValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config := config.GetDefault(config.ConfServer)
	config.SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	var iv *IMAVerifier

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
			10: "495fae6cef47018b3b4af87ba89e90d9ccef3089",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}

	item := entity.ManifestItem{
		Name:   "boot_aggregate",
		Value:  "6963796540f9a94a8770f6dea2038d5a1a8b6a21",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"52e5667be7d60a7ade219948519ee280fb9c6aff\",\"TemplateName\":\"ima\",\"FiledataHash\":\"6963796540f9a94a8770f6dea2038d5a1a8b6a21\",\"FilenameHint\":\"boot_aggregate\"}",
	}
	item2 := entity.ManifestItem{
		Name:   "hint2",
		Value:  "cc7337642a6dd41d45203ca8085727d2bbc1569a",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"8bbbc2b6f723dc32808a10ecdf48fe254db336d1\",\"TemplateName\":\"ima\",\"FiledataHash\":\"cc7337642a6dd41d45203ca8085727d2bbc1569a\",\"FilenameHint\":\"hint2\"}",
	}
	item3 := entity.ManifestItem{
		Name:   "hint3",
		Value:  "cc7337642a6dd41d45203ca8085727d2bbc1569a",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"738fad65e6b8366d167b34f7e76688fbc3af8024\",\"TemplateName\":\"ima\",\"FiledataHash\":\"cc7337642a6dd41d45203ca8085727d2bbc1569a\",\"FilenameHint\":\"hint3\"}",
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

	pibv1 := entity.PcrInfo{
		Values: map[int]string{
			0:  sha1HashAllZero,
			1:  "073ee1e91b686efef30ec49f081fe93355de389e",
			2:  sha1HashAllZero,
			3:  "34ac889f14ac927f1198daf306f9da76dde64a9f",
			4:  sha1HashAllZero,
			5:  sha1HashAllZero,
			6:  sha1HashAllZero,
			7:  sha1HashAllZero,
			10: "ba50b739ca51b77deba25d0ce9cee00f39820c13",
		},
		Quote: entity.PcrQuote{
			Quoted: []byte(quoteVal),
		},
	}
	item4 := entity.ManifestItem{
		Name:   "boot_aggregate",
		Value:  "sha1:6963796540f9a94a8770f6dea2038d5a1a8b6a21",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"04f89f802b9453d7952748cee55f58a0f34686c5\",\"TemplateName\":\"ima-ng\",\"FiledataHash\":\"sha1:6963796540f9a94a8770f6dea2038d5a1a8b6a21\",\"FilenameHint\":\"boot_aggregate\"}",
	}
	item5 := entity.ManifestItem{
		Name:   "hint2",
		Value:  "sha1:cc7337642a6dd41d45203ca8085727d2bbc1569a",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"e4fb65643b608c6800c35008f278a8ab92e04d71\",\"TemplateName\":\"ima-ng\",\"FiledataHash\":\"sha1:cc7337642a6dd41d45203ca8085727d2bbc1569a\",\"FilenameHint\":\"hint2\"}",
	}
	item6 := entity.ManifestItem{
		Name:   "hint3",
		Value:  "sha1:cc7337642a6dd41d45203ca8085727d2bbc1569a",
		Detail: "{\"Pcr\":\"10\",\"TemplateHash\":\"9592ab9e18b97bc32ccb08285778f32148f6e801\",\"TemplateName\":\"ima-ng\",\"FiledataHash\":\"sha1:cc7337642a6dd41d45203ca8085727d2bbc1569a\",\"FilenameHint\":\"hint3\"}",
	}
	mf1 := entity.Manifest{
		Type:  mtIMA,
		Items: []entity.ManifestItem{item4, item5, item6},
	}

	report1 := &entity.Report{
		PcrInfo:  pibv1,
		Manifest: []entity.Manifest{mf1},
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
		{report1, nil},
	}
	for i := 0; i < len(testCase); i++ {
		err := iv.Validate(testCase[i].input)
		res := testCase[i].result
		if err == res || (res != nil && err.Error() == testCase[i].result.Error()) {
			t.Logf("test ima Validate success at case %d\n", i)
		} else {
			t.Errorf("test ima Validate error at case %d: %v\n", i, err)
		}
	}
}

func TestPCRValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	var pv *PCRVerifier

	//client id = 40
	const quoted = "\xffTCG\x80\x18\x00\"\x00\v\x10\f\xedƬ\xd6z\x1e\xbb\xd3}H\xb0\x12\"bb\xe3ȳ\x8a\xc2?u\xf4n{^\xbdԝ\x10\x00 \x1e\xb4\xa0LrU\\\xcb*\x04\xd5*\xd1T?Zi>\x97\xdcC 4c\xa8\xc0D\xd8r\xae\x1b!\x00\x00\x00\x00\x00\x00\x11\xb3\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x17\x06\x19\x00\x1666\x00\x00\x00\x01\x00\x04\x03\xff\xff\xff\x00 ?'\b> \xdb|\v\xf0\xe3\x16!\x19\x00\xa9\nS\xe9\x9e\xf1*hb.\x89y'\x93Y\x88\x03\xd2"
	const signature = "{\"Alg\":20,\"RSA\":{\"HashAlg\":11,\"Signature\":\"V5zxeJ9+LwkTShUJbdYqyFG8r8+aTWzTg4JRX8DEinMvzIKZ04TfzOVpM3k+EAcECp/E43oS/yqExUHR9cCq4WN1PHhL1S998GTt4ZknkzluhmEh6EaaezcsAuJPDDBNkwbq/eJt3uoi2HSs18pJ7O1cdvEFPPfrRZvlTOFm+aAdcn0eW4WUVk3r/kw2cLlH7EuRIbwecPzG9yPwt9C/6dTKJpaw7qVoj57oKObdyvpzE6J/ylEXgDro3fk2cYinvTxkob+jlThNDydZwU0Iamtsy1d8NS5qvA0kzqUcueLEgvfaLT4IaPZVeN0G/U4q8qpzLXc7c4EGECt3AkIPMQ==\"},\"ECC\":null}"
	pibv := entity.PcrInfo{
		Values: map[int]string{
			0:  sha1HashAllZero,
			1:  sha1HashAllZero,
			2:  sha1HashAllZero,
			3:  sha1HashAllZero,
			4:  sha1HashAllZero,
			5:  sha1HashAllZero,
			6:  sha1HashAllZero,
			7:  sha1HashAllZero,
			8:  sha1HashAllZero,
			9:  sha1HashAllZero,
			10: sha1HashAllZero,
			11: sha1HashAllZero,
			12: sha1HashAllZero,
			13: sha1HashAllZero,
			14: sha1HashAllZero,
			15: sha1HashAllZero,
			16: sha1HashAllZero,
			17: sha1HashAllFF,
			18: sha1HashAllFF,
			19: sha1HashAllFF,
			20: sha1HashAllFF,
			21: sha1HashAllFF,
			22: sha1HashAllFF,
			23: sha1HashAllZero,
		},
		Quote: entity.PcrQuote{
			Quoted:    []byte(quoted),
			Signature: []byte(signature),
		},
	}

	ci := &entity.ClientInfo{
		Info: map[string]string{
			"info name1": "info value1",
			"info name2": "info value2",
		},
	}
	psd, err := dao.CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()
	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic, true)
	if err != nil {
		t.Error(err)
	}

	rc := entity.RegisterClient{
		ClientID:      cid,
		AkCertificate: "-----BEGIN CERTIFICATE-----\nMIIC+TCCAeGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA3MQ4wDAYDVQQGEwVDaGlu\nYTEQMA4GA1UEChMHQ29tcGFueTETMBEGA1UEAxMKcHJpdmFjeSBjYTAeFw0yMTEy\nMTEwNjQ0MzdaFw0yMjEyMTEwNjQ0MzdaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC3oz7yfwjBCeGD+1NUboYNI14F7BeTI7BGZcFp4j8ABG2ABSXh\npje2ot+iiywx7vkEFb2OX6HYzb1RLQWeg6bn4tR+/zWYyTtnYzRO5EI6qflcPpqG\nDoDqICM0fs6tzOLcr443rfmN5Ju5MLv546+4o6xUZA2VCOant5U4bxXO2tPuUiNG\nnxYrBQXO+LCFlCRzA9kF5ckoCVi5uGyadwx1/K69I70O4T2KZK3Fy0Ssg0ZFWM7K\nlwnp0zEt5ZS/UaSOASBQl/Vc4WW3IB9v5pFvGfDY6i7OPULnLFkcPuh2ueBpafF2\nLJ+Tfsbb5zTLYnQKotrbXOeMcX4jnv/R/4mPAgMBAAGjRzBFMA4GA1UdDwEB/wQE\nAwICpDAfBgNVHSMEGDAWgBTNFcdAexj1Ezk8FEfjeBqH+1CidTASBgNVHREBAf8E\nCDAGhwTAqNGhMA0GCSqGSIb3DQEBCwUAA4IBAQACj2NBejgFSoP6aJ4Ib6rVBrX9\nQwCK57MRdRMUaahGbKCKkcwYjuccwZs9pL6mdTqS7KD+SFUwm2SBOD2eU8FbBFqZ\n1OQ3qPievIpnJXkWHVEIBAZEtH9P+Jl3zmfM21DNqZLJJRdcMdFRcug+EooSIdbP\nHuc2tP1RJFe5oSClY1FvQTotpEKQHMxrFWoaYaZarrmx65xfqr8EWYMeMw5YCiOI\n6aL+MQm1uDmhoCMuBtzIOx7GriA8ixXCGaYyXBVd2P7zVaM5P5/8R0g91Tmbhu8i\nV2oVs0zFRO17AmsA/FQDJxMiXGux1DBkEBwgL3QUBcHmRqGabk45VZRAD6Hl\n-----END CERTIFICATE-----\n",
	}
	err = trustmgr.UpdateRegisterClient(&rc)
	if err != nil {
		t.Error(err)
	}

	testreport1 := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{},
		ClientID: cid,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}
	testreport2 := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{},
		ClientID: 100,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}
	testCase := []struct {
		input  *entity.Report
		result error
	}{
		{testreport1, nil},
		{testreport2, fmt.Errorf("get register client information failed")},
	}
	for i := 0; i < len(testCase); i++ {
		err := pv.Validate(testCase[i].input)
		res := testCase[i].result
		if err == res || (res != nil && err.Error() == testCase[i].result.Error()) {
			t.Logf("test pcr validate success at case %d\n", i)
		} else {
			t.Errorf("test pcr Validate error at case %d: %v\n", i, err)
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

func TestVerifierMgrValidate(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	vm, err := CreateVerifierMgr()
	if err != nil {
		t.Fatalf("%v", err)
	}

	const quoted = "\xffTCG\x80\x18\x00\"\x00\v\x10\f\xedƬ\xd6z\x1e\xbb\xd3}H\xb0\x12\"bb\xe3ȳ\x8a\xc2?u\xf4n{^\xbdԝ\x10\x00 \x1e\xb4\xa0LrU\\\xcb*\x04\xd5*\xd1T?Zi>\x97\xdcC 4c\xa8\xc0D\xd8r\xae\x1b!\x00\x00\x00\x00\x00\x00\x11\xb3\x00\x00\x00\x01\x00\x00\x00\x00\x01 \x17\x06\x19\x00\x1666\x00\x00\x00\x01\x00\x04\x03\xff\xff\xff\x00 ?'\b> \xdb|\v\xf0\xe3\x16!\x19\x00\xa9\nS\xe9\x9e\xf1*hb.\x89y'\x93Y\x88\x03\xd2"
	const signature = "{\"Alg\":20,\"RSA\":{\"HashAlg\":11,\"Signature\":\"V5zxeJ9+LwkTShUJbdYqyFG8r8+aTWzTg4JRX8DEinMvzIKZ04TfzOVpM3k+EAcECp/E43oS/yqExUHR9cCq4WN1PHhL1S998GTt4ZknkzluhmEh6EaaezcsAuJPDDBNkwbq/eJt3uoi2HSs18pJ7O1cdvEFPPfrRZvlTOFm+aAdcn0eW4WUVk3r/kw2cLlH7EuRIbwecPzG9yPwt9C/6dTKJpaw7qVoj57oKObdyvpzE6J/ylEXgDro3fk2cYinvTxkob+jlThNDydZwU0Iamtsy1d8NS5qvA0kzqUcueLEgvfaLT4IaPZVeN0G/U4q8qpzLXc7c4EGECt3AkIPMQ==\"},\"ECC\":null}"
	pibv := entity.PcrInfo{
		Values: map[int]string{
			0:  sha1HashAllZero,
			1:  sha1HashAllZero,
			2:  sha1HashAllZero,
			3:  sha1HashAllZero,
			4:  sha1HashAllZero,
			5:  sha1HashAllZero,
			6:  sha1HashAllZero,
			7:  sha1HashAllZero,
			8:  sha1HashAllZero,
			9:  sha1HashAllZero,
			10: sha1HashAllZero,
			11: sha1HashAllZero,
			12: sha1HashAllZero,
			13: sha1HashAllZero,
			14: sha1HashAllZero,
			15: sha1HashAllZero,
			16: sha1HashAllZero,
			17: sha1HashAllFF,
			18: sha1HashAllFF,
			19: sha1HashAllFF,
			20: sha1HashAllFF,
			21: sha1HashAllFF,
			22: sha1HashAllFF,
			23: sha1HashAllZero,
		},
		Quote: entity.PcrQuote{
			Quoted:    []byte(quoted),
			Signature: []byte(signature),
		},
	}

	ci := &entity.ClientInfo{
		Info: map[string]string{
			"info name1": "info value1",
			"info name2": "info value2",
		},
	}
	psd, err := dao.CreatePostgreSQLDAO()
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer psd.Destroy()
	ic := createRandomCert()
	cid, err := psd.RegisterClient(ci, ic, true)
	if err != nil {
		t.Error(err)
	}

	rc := entity.RegisterClient{
		ClientID:      cid,
		AkCertificate: "-----BEGIN CERTIFICATE-----\nMIIC+TCCAeGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA3MQ4wDAYDVQQGEwVDaGlu\nYTEQMA4GA1UEChMHQ29tcGFueTETMBEGA1UEAxMKcHJpdmFjeSBjYTAeFw0yMTEy\nMTEwNjQ0MzdaFw0yMjEyMTEwNjQ0MzdaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQC3oz7yfwjBCeGD+1NUboYNI14F7BeTI7BGZcFp4j8ABG2ABSXh\npje2ot+iiywx7vkEFb2OX6HYzb1RLQWeg6bn4tR+/zWYyTtnYzRO5EI6qflcPpqG\nDoDqICM0fs6tzOLcr443rfmN5Ju5MLv546+4o6xUZA2VCOant5U4bxXO2tPuUiNG\nnxYrBQXO+LCFlCRzA9kF5ckoCVi5uGyadwx1/K69I70O4T2KZK3Fy0Ssg0ZFWM7K\nlwnp0zEt5ZS/UaSOASBQl/Vc4WW3IB9v5pFvGfDY6i7OPULnLFkcPuh2ueBpafF2\nLJ+Tfsbb5zTLYnQKotrbXOeMcX4jnv/R/4mPAgMBAAGjRzBFMA4GA1UdDwEB/wQE\nAwICpDAfBgNVHSMEGDAWgBTNFcdAexj1Ezk8FEfjeBqH+1CidTASBgNVHREBAf8E\nCDAGhwTAqNGhMA0GCSqGSIb3DQEBCwUAA4IBAQACj2NBejgFSoP6aJ4Ib6rVBrX9\nQwCK57MRdRMUaahGbKCKkcwYjuccwZs9pL6mdTqS7KD+SFUwm2SBOD2eU8FbBFqZ\n1OQ3qPievIpnJXkWHVEIBAZEtH9P+Jl3zmfM21DNqZLJJRdcMdFRcug+EooSIdbP\nHuc2tP1RJFe5oSClY1FvQTotpEKQHMxrFWoaYaZarrmx65xfqr8EWYMeMw5YCiOI\n6aL+MQm1uDmhoCMuBtzIOx7GriA8ixXCGaYyXBVd2P7zVaM5P5/8R0g91Tmbhu8i\nV2oVs0zFRO17AmsA/FQDJxMiXGux1DBkEBwgL3QUBcHmRqGabk45VZRAD6Hl\n-----END CERTIFICATE-----\n",
	}
	err = trustmgr.UpdateRegisterClient(&rc)
	if err != nil {
		t.Error(err)
	}

	testreport1 := &entity.Report{
		PcrInfo:  pibv,
		Manifest: []entity.Manifest{},
		ClientID: cid,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}

	testCase := []struct {
		input  *entity.Report
		result error
	}{
		{testreport1, fmt.Errorf("no bios manifest in report")},
	}
	for i := 0; i < len(testCase); i++ {
		err := vm.Validate(testCase[i].input)
		res := testCase[i].result
		if err == res || (res != nil && err.Error() == testCase[i].result.Error()) {
			t.Logf("test VerifierMgr validate success at case %d\n", i)
		} else {
			t.Errorf("test VerifierMgr Validate error at case %d: %v\n", i, err)
		}
	}

}

func TestVerifierMgrVerify(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	vm, err := CreateVerifierMgr()
	if err != nil {
		t.Fatalf("%v", err)
	}

	baseValue := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{bmea, bmea2, imea, imea2},
	}

	testReport := &entity.Report{
		Manifest: []entity.Manifest{bm, im},
	}

	baseValue2 := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{bmea, bmea2},
	}

	testReport2 := &entity.Report{
		Manifest: []entity.Manifest{bm},
	}

	baseValue3 := &entity.MeasurementInfo{
		Manifest: []entity.Measurement{imea, imea2},
	}

	testReport3 := &entity.Report{
		Manifest: []entity.Manifest{im},
	}

	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue, testReport, nil},
		{baseValue2, testReport2, nil},
		{baseValue3, testReport3, nil},
	}
	for i := 0; i < len(testCase); i++ {
		err := vm.Verify(testCase[i].input1, testCase[i].input2)
		res := testCase[i].result
		if err == res || (res != nil && err != nil && err.Error() == res.Error()) {
			t.Logf("test VerifierMgr Verify success at case %d\n", i)
		} else {
			t.Errorf("test VerifierMgr Verify error at case %d: %v\n", i, err)
		}
	}
}

func TestVerifierMgrExtract(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer).SetDigestAlgorithm(sha1AlgStr)
	defer test.RemoveConfigFile()
	vm, err := CreateVerifierMgr()
	if err != nil {
		t.Fatalf("%v", err)
	}

	testReport := &entity.Report{
		PcrInfo:  pi,
		Manifest: []entity.Manifest{im, bm},
	}
	testReport2 := &entity.Report{
		PcrInfo:  pi,
		Manifest: []entity.Manifest{im2, bm2},
	}
	testMea := &entity.MeasurementInfo{}
	testMea2 := &entity.MeasurementInfo{}
	testCase := []struct {
		input1 *entity.Report
		input2 *entity.MeasurementInfo
		result error
	}{
		{testReport, testMea, nil},
		{testReport2, testMea2, errors.New("extract failed. bios manifest name name2 doesn't exist in this report")},
	}
	for i := 0; i < len(testCase); i++ {
		err := vm.Extract(testCase[i].input1, testCase[i].input2)
		res := testCase[i].result
		if err == res || (res != nil && err != nil && err.Error() == res.Error()) {
			t.Logf("test VerifierMgr extract success at case %d\n", i)
		} else {
			t.Errorf("test VerifierMgr extract error at case %d: %v\n", i, err)
		}
	}
}
