/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2022-01-17
Description: config package for ras.
*/

package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"github.com/stretchr/testify/assert"
)

const (
	testString1 = "abcdef12345"
	testString2 = "123#$%^&*()!@#"
	testString3 = "zxcdfeaonasdfasdf"
)
const clientConfig = `
log:
  path: "./rac-log.txt"
racconfig:
  ikpkey: ""
  ikcert: ""
  ekpkeytest: ""
  ekcerttest: ""
  ikpkeytest: ""
  ikcerttest: ""
  server: 127.0.0.1:40001
  hbduration: 5s
  trustduration: 2m0s
  clientId: -1
  password: ""
  digestalgorithm: sha256
`

const hubConfig = `
log:
  path: "./rahub-log.txt"
hubconfig:
  server: 127.0.0.1:40001
  hubport: "127.0.0.1:40003"
`

const serverConfig = `
database:
  host: localhost
  name: kunpengsecl
  password: postgres
  port: 5432
  user: postgres
log:
  file: ./logs/ras-log.txt
racconfig:
  digestalgorithm: sha1
  hbduration: 10s
  trustduration: 2m0s
rasconfig:
  authkeyfile: ./ecdsakey.pub
  pcakeycertfile: ""
  pcaprivkeyfile: ""
  restport: 127.0.0.1:40002
  rootkeycertfile: ""
  rootprivkeyfile: ""
  serialnumber: 0
  serverport: 127.0.0.1:40001
  onlineduration: 30s
  basevalue-extract-rules:
    manifest:
    - name:
      - 8-0
      - 80000008-1
      type: bios
    - name:
      - boot_aggregate
      - /etc/modprobe.d/tuned.conf
      type: ima
    pcrinfo:
      pcrselection:
      - 1
      - 2
      - 3
      - 4
`

const configFilePath = "./config.yaml"

var (
	testCases1 = []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}

	testCases2 = []int{0, 10086, 65535}

	testCases3 = []time.Duration{time.Second, time.Second * 100}
)

func CreateClientConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(clientConfig), 0644)
}

func CreateHubConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(hubConfig), 0644)
}

func CreateServerConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(serverConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func TestRASConfig1(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()
	//InitRasFlags()
	InitFlags()
	LoadConfigs()
	HandleFlags()

	for i := 0; i < len(testCases1); i++ {
		SetDBHost(testCases1[i].input)
		if GetDBHost() != testCases1[i].result {
			t.Errorf("test host error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetDBUser(testCases1[i].input)
		if GetDBUser() != testCases1[i].result {
			t.Errorf("test user error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetDBPassword(testCases1[i].input)
		if GetDBPassword() != testCases1[i].result {
			t.Errorf("test user error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetAuthKeyFile(testCases1[i].input)
		if GetAuthKeyFile() != testCases1[i].result {
			t.Errorf("test AuthKeyFile error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetDBName(testCases1[i].input)
		if GetDBName() != testCases1[i].result {
			t.Errorf("test DBName error at case %d\n", i)
		}
	}
}

func TestRASConfig2(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()

	LoadConfigs()
	HandleFlags()

	for i := 0; i < len(testCases1); i++ {
		SetServerPort(testCases1[i].input)
		if GetServerPort() != testCases1[i].result {
			t.Errorf("test ServerPort error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases1); i++ {
		SetRestPort(testCases1[i].input)
		if GetRestPort() != testCases1[i].result {
			t.Errorf("test RestPort error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases2); i++ {
		SetDBPort(testCases2[i])
		if GetDBPort() != testCases2[i] {
			t.Errorf("test DBPort error at case %d\n", i)
		}
	}
	for i := 0; i < len(testCases3); i++ {
		SetOnlineDuration(testCases3[i])
		if GetOnlineDuration() != testCases3[i] {
			t.Errorf("test DBPort error at case %d\n", i)
		}
	}

	if GetRootKeyCert() == nil {
		t.Errorf("test DBPort error")
	}
	GetRootKeyCert()
	GetRootPrivateKey()
	GetPcaKeyCert()
	GetPcaPrivateKey()
	GetHttpsKeyCert()
	GetHttpsPrivateKey()
	GetDigestAlgorithm()

	testExRule := typdefs.ExtractRules{
		PcrRule: typdefs.PcrRule{PcrSelection: []int{1, 2, 3, 4}},
		ManifestRules: []typdefs.ManifestRule{
			0: {MType: "bios", Name: []string{"8-0", "80000008-1"}},
			1: {MType: "ima", Name: []string{"boot_aggregate", "/etc/modprobe.d/tuned.conf"}},
		},
	}
	tt := GetExtractRules()
	fmt.Println(tt)
	assert.Equal(t, testExRule, GetExtractRules())

	os.Remove(rasCfg.rootKeyCertFile)
	os.Remove(rasCfg.rootPrivKeyFile)
	os.Remove(rasCfg.pcaKeyCertFile)
	os.Remove(rasCfg.pcaPrivKeyFile)
	os.Remove(rasCfg.httpsKeyCertFile)
	os.Remove(rasCfg.httpsPrivKeyFile)
}

func testHBDuration(t *testing.T) {
	LoadConfigs()

	testCases1 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases1); i++ {
		SetHBDuration(testCases1[i].input)
		if GetHBDuration() != testCases1[i].result {
			t.Errorf("test hbDuration error at case %d\n", i)
		}
	}
}

func testTrustDuration(t *testing.T) {
	LoadConfigs()
	testCases2 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases2); i++ {
		SetTrustDuration(testCases2[i].input)
		if GetTrustDuration() != testCases2[i].result {
			t.Errorf("test trustDuration error at case %d\n", i)
		}
	}
}

func TestRACConfig(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	//InitRasFlags()

	LoadConfigs()
	HandleFlags()

	testHBDuration(t)
	testTrustDuration(t)

	SaveConfigs()
	os.Remove(rasCfg.rootKeyCertFile)
	os.Remove(rasCfg.rootPrivKeyFile)
	os.Remove(rasCfg.pcaKeyCertFile)
	os.Remove(rasCfg.pcaPrivKeyFile)
	os.Remove(rasCfg.httpsKeyCertFile)
	os.Remove(rasCfg.httpsPrivKeyFile)
}
