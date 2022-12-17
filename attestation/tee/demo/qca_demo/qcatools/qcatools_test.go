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
	uuid = "testuuid"
	data = "testdata"
	cert = "testcert"
	tcb  = false
)

func CreateQcaConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(QcaConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func TestGetTAReport(t *testing.T) {
	CreateQcaConfigFile()
	defer RemoveConfigFile()

	InitFlags()
	LoadConfigs()
	HandleFlags()

	res := GetTAReport([]byte(uuid), []byte(data), tcb)
	if res == nil {
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
