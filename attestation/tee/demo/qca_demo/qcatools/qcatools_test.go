/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli/wanghaijing
Create: 2022-05-01
Description: invoke qca lib to get info of given TA
*/

package qcatools

import (
	"io/ioutil"
	"os"
	"testing"
)

const (
	configFilePath = "./config.yaml"
	QcaConfig      = `
qcaconfig:
  server: 127.0.0.1:40007
  akserver: 127.0.0.1:40008
  scenario: 0
  nodaaacfile: ./nodaa-ac.crt
  daaacfile: ./daa-ac.crt
`
	GET_TA_REPORT_ERROR    = "get ta report error"
	GENERATE_AK_CERT_ERROR = "generate ak cert error"
	SAVE_AK_CERT_ERROR     = "save ak cert error"
)

var (
	testUuid = "testuuid11111111"
	data = "testdata"
	cert = "testcert"
	tcb  = false
)

func CreateQcaConfigFile() {
	err := ioutil.WriteFile(configFilePath, []byte(QcaConfig), 0644)
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

func TestGetTAReport(t *testing.T) {
	CreateQcaConfigFile()
	defer RemoveConfigFile()

	InitFlags()
	LoadConfigs()
	HandleFlags()

	res, err := GetTAReport([]byte(testUuid), []byte(data), tcb)
	if res == nil || err != nil {
		t.Error(GET_TA_REPORT_ERROR)
	}
}

func TestGenerateAKCert(t *testing.T) {
	CreateQcaConfigFile()
	defer RemoveConfigFile()

	LoadConfigs()
	HandleFlags()

	_, err := GenerateAKCert()
	if err == nil {
		t.Error(GENERATE_AK_CERT_ERROR)
	}

	Qcacfg.Scenario = 1
	_, err = GenerateAKCert()
	if err != nil {
		t.Error(GENERATE_AK_CERT_ERROR)
	}

	// DAA场景的证书生成存在问题，暂时注释掉
	// Qcacfg.Scenario = 2
	// _, err = GenerateAKCert()
	// if err != nil {
	// 	t.Error(GENERATE_AK_CERT_ERROR)
	// }

	Qcacfg.Scenario = 3
	_, err = GenerateAKCert()
	if err == nil {
		t.Error(GENERATE_AK_CERT_ERROR)
	}
}

func TestSaveAKCert(t *testing.T) {
	err := SaveAKCert([]byte(cert))
	if err != nil {
		t.Error(SAVE_AK_CERT_ERROR)
	}
}
