/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

package main

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const (
	testString1    = "abcdef12345"
	testString2    = "123#$%^&*()!@#"
	testString3    = "zxcdfeaonasdfasdf"
	configFilePath = "./config.yaml"
	clientConfig   = `
log:
  path: "./rac-log.txt"
racconfig:
  ecfile: ""
  icfile: ""
  ectestfile: ""
  ictestfile: ""
  server: 127.0.0.1:40001
  hbduration: 5s
  trustduration: 2m0s
  clientId: -1
  password: ""
  digestalgorithm: sha256
  seed: 1
`
)

var (
	testCases1 = []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}
	testCases2 = []struct {
		input  int64
		result int64
	}{
		{-1, -1},
		{1, 1},
		{1000, 1000},
	}
	testCases3 = []struct {
		input  string
		result string
	}{
		{nullString, nullString},
		{GetServer(), GetServer()},
	}
	testCases4 = []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	testCases5 = []struct {
		input  string
		result string
	}{
		{"sha256", "sha256"},
		{"sha1", "sha1"},
		{"sm3", "sm3"},
	}
)

func CreateClientConfigFile() {
	err := ioutil.WriteFile(configFilePath, []byte(clientConfig), 0644)
	if err != nil {
		return
	}
}

func RemoveConfigFile() {
	err := os.Remove(configFilePath)
	if err != nil {
		return
	}
}

func TestConfigNotInTestMode(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()

	initFlags()
	loadConfigs()
	handleFlags()
	if GetTestMode() {
		t.Error("test set testmode error")
	}

	for i := 0; i < len(testCases1); i++ {
		SetEKeyCert([]byte(testCases1[i].input))
		if string(GetEKeyCert()) != testCases1[i].result {
			t.Errorf("test EKeyCert error at case %d in mod false\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetIKeyCert([]byte(testCases1[i].input))
		if string(GetIKeyCert()) != testCases1[i].result {
			t.Errorf("test IKeyCert error at case %d in mod false\n", i)
		}
	}
	for i := 0; i < len(testCases2); i++ {
		SetClientId(testCases2[i].input)
		if GetClientId() != testCases2[i].result {
			t.Errorf("test ClientId error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases3); i++ {
		SetServer(testCases3[i].input)
		if GetServer() != testCases3[i].result {
			t.Errorf("test Server error at case %d\n", i)
		}
	}
	saveConfigs()
}
func TestDurations(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()

	loadConfigs()
	handleFlags()

	for i := 0; i < len(testCases4); i++ {
		SetHBDuration(testCases4[i].input)
		if GetHBDuration() != testCases4[i].result {
			t.Errorf("test hbDuration error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases4); i++ {
		SetTrustDuration(testCases4[i].input)
		if GetTrustDuration() != testCases4[i].result {
			t.Errorf("test trustDuration error at case %d\n", i)
		}
	}
}

func TestConfigInTestMode(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()

	loadConfigs()
	s := viper.GetString(confServer)
	test := true
	server = &s
	testMode = &test
	handleFlags()

	if !GetTestMode() {
		t.Error("test set testmode error")
	}
	for i := 0; i < len(testCases1); i++ {
		SetEKeyCert([]byte(testCases1[i].input))
		if string(GetEKeyCert()) != testCases1[i].result {
			t.Errorf("test EKeyCert error at case %d in mod true\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetIKeyCert([]byte(testCases1[i].input))
		if string(GetIKeyCert()) != testCases1[i].result {
			t.Errorf("test IKeyCert error at case %d in mod true\n", i)
		}
	}
	for i := 0; i < len(testCases5); i++ {
		SetDigestAlgorithm(testCases5[i].input)
		if GetDigestAlgorithm() != testCases5[i].result {
			t.Errorf("test DigestAlgorithm error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases2); i++ {
		SetSeed(testCases2[i].input)
		if GetSeed() != testCases2[i].result {
			t.Errorf("test seed error at case %d\n", i)
		}
	}

	getEKCert()
	getIKCert()
	GetLogPath()
	saveConfigs()

	err1 := os.Remove(racCfg.ecTestFile)
	if err1 != nil {
		t.Errorf("remove error: %v", err1)
	}
	err2 := os.Remove(racCfg.icTestFile)
	if err2 != nil {
		t.Errorf("remove error: %v", err2)
	}
	err3 := os.Remove(racCfg.ecFile)
	if err3 != nil {
		t.Errorf("remove error: %v", err3)
	}
	err4 := os.Remove(racCfg.icFile)
	if err4 != nil {
		t.Errorf("remove error: %v", err4)
	}
}
