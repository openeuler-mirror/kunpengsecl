package config

import (
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/stretchr/testify/assert"
)

const (
	testString1 = "abcdef12345"
	testString2 = "123#$%^&*()!@#"
	testString3 = "zxcdfeaonasdfasdf"
)

func TestRASConfig(t *testing.T) {
	test.CreateServerConfigFile()
	defer test.RemoveConfigFile()
	confG = nil
	//InitRasFlags()
	GetDefault(ConfServer)
	Save()
	confG = nil
	config := GetDefault(ConfServer)

	testCases1 := []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetMgrStrategy(testCases1[i].input)
		if config.GetMgrStrategy() != testCases1[i].result {
			t.Errorf("test mgrStrategy error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetHost(testCases1[i].input)
		if config.GetHost() != testCases1[i].result {
			t.Errorf("test host error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetUser(testCases1[i].input)
		if config.GetUser() != testCases1[i].result {
			t.Errorf("test user error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetPassword(testCases1[i].input)
		if config.GetPassword() != testCases1[i].result {
			t.Errorf("test user error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetAuthKeyFile(testCases1[i].input)
		if config.GetAuthKeyFile() != testCases1[i].result {
			t.Errorf("test AuthKeyFile error at case %d\n", i)
		}
	}

	testExRule := entity.ExtractRules{
		PcrRule: entity.PcrRule{PcrSelection: []int{1, 2, 3}},
		ManifestRules: []entity.ManifestRule{
			1: {MType: "bios", Name: []string{"name1", "name2"}},
		},
	}
	config.SetExtractRules(testExRule)
	assert.Equal(t, testExRule, config.GetExtractRules())

	testAuc1 := true
	testAuc2 := []int64{1, 4, 5}
	config.SetAutoUpdateConfig(entity.AutoUpdateConfig{
		IsAllUpdate:   testAuc1,
		UpdateClients: testAuc2,
	})
	auc := config.GetAutoUpdateConfig()
	assert.Equal(t, testAuc1, auc.IsAllUpdate)
	assert.Equal(t, testAuc2, auc.UpdateClients)
	Save()
	os.Remove(config.rasConfig.rootPrivKeyFile)
	os.Remove(config.rasConfig.rootKeyCertFile)
	os.Remove(config.rasConfig.pcaPrivKeyFile)
	os.Remove(config.rasConfig.pcaKeyCertFile)
}

func TestRACConfig(t *testing.T) {
	test.CreateClientConfigFile()
	defer test.RemoveConfigFile()
	confG = nil
	InitRacFlags()
	SetupSignalHandler()
	*racTestMode = true
	config := GetDefault(ConfClient)

	testCases1 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetHBDuration(testCases1[i].input)
		if config.GetHBDuration() != testCases1[i].result {
			t.Errorf("test hbDuration error at case %d\n", i)
		}
	}

	testCases2 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases2); i++ {
		config.SetTrustDuration(testCases2[i].input)
		if config.GetTrustDuration() != testCases2[i].result {
			t.Errorf("test trustDuration error at case %d\n", i)
		}
	}

	testCases3 := []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}
	for i := 0; i < len(testCases3); i++ {
		config.SetEKeyCert([]byte(testCases3[i].input))
		if string(config.GetEKeyCert()) != testCases3[i].result {
			t.Errorf("test EKeyCert error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases3); i++ {
		config.SetEKeyCertTest([]byte(testCases3[i].input))
		if string(config.GetEKeyCertTest()) != testCases3[i].result {
			t.Errorf("test EKeyCertTest error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases3); i++ {
		config.SetIKeyCert([]byte(testCases3[i].input))
		if string(config.GetIKeyCert()) != testCases3[i].result {
			t.Errorf("test IKeyCert error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases3); i++ {
		config.SetIKeyCertTest([]byte(testCases3[i].input))
		if string(config.GetIKeyCertTest()) != testCases3[i].result {
			t.Errorf("test IKeyCertTest error at case %d\n", i)
		}
	}

	testCases4 := []struct {
		input  int64
		result int64
	}{
		{-1, -1},
		{1, 1},
		{1000, 1000},
	}
	for i := 0; i < len(testCases4); i++ {
		config.SetClientId(testCases4[i].input)
		if config.GetClientId() != testCases4[i].result {
			t.Errorf("test ClientId error at case %d\n", i)
		}
	}

	Save()
	confG = nil
	*racTestMode = true
	config = GetDefault(ConfClient)
	if !config.GetTestMode() {
		t.Errorf("test TestMode error\n")
	}
	confG = nil
	*racTestMode = false
	config = GetDefault(ConfClient)
	if config.GetTestMode() {
		t.Errorf("test TestMode error\n")
	}
}

func TestRAHubConfig(t *testing.T) {
	test.CreateHubConfigFile()
	defer test.RemoveConfigFile()
	confG = nil
	//InitHubFlags()
	config := GetDefault(ConfHub)
	Save()

	config.GetHubPort()
	config.GetHubServer()
}
