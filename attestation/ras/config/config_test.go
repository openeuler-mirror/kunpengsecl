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

	test1 := true
	test2 := []int64{1, 4, 5}
	config.SetAutoUpdateConfig(entity.AutoUpdateConfig{
		IsAllUpdate:   test1,
		UpdateClients: test2,
	})
	auc := config.GetAutoUpdateConfig()
	assert.Equal(t, test1, auc.IsAllUpdate)
	assert.Equal(t, test2, auc.UpdateClients)
	Save()
	os.Remove(config.rasConfig.rootPrivKeyFile)
	os.Remove(config.rasConfig.rootKeyCertFile)
	os.Remove(config.rasConfig.pcaPrivKeyFile)
	os.Remove(config.rasConfig.pcaKeyCertFile)
}

func TestRACConfig(t *testing.T) {
	test.CreateClientConfigFile()
	defer test.RemoveConfigFile()
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
}
