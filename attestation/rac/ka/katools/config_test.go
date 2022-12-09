package katools

import (
	"io/ioutil"
	"os"
	"testing"
)

const (
	configFilePath = "./config.yaml"
	clientKaConfig = `
kaconfig:
  pollduration: 3s
  ccFile: ./cert/ca.crt
  kcFile: ./cert/kta.crt
  kKeyFile: ./cert/kta.key
`
)

func CreateClientConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(clientKaConfig), 0644)
}
func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func TestGetPollDuration(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	loadConfigs()
	polldur := GetPollDuration()
	if polldur == 0 {
		t.Errorf("Get poll duration error\n")
	}
	t.Logf("polldur=%v\n", polldur)
}

func TestGetCaCertFile(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	loadConfigs()
	caCert := getCaCertFile()
	if caCert == nullString {
		t.Errorf("Get ca cert file error\n")
	}
	t.Logf("caCert=%v\n", caCert)
}
func TestGetKtaCertFile(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	loadConfigs()
	ktaCert := getKtaCertFile()
	if ktaCert == nullString {
		t.Errorf("Get kta cert file error\n")
	}
	t.Logf("ktaCert=%v\n", ktaCert)
}

func TestGetKtaKeyFile(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	loadConfigs()
	ktaKey := getKtaKeyFile()
	if ktaKey == nullString {
		t.Errorf("Get kta key file error\n")
	}
	t.Logf("ktaCert=%v\n", ktaKey)
}
