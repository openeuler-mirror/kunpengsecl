package main

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
)

const Config = `
log:
  path: "./rahub-log.txt"
hubconfig:
  server: 127.0.0.1:40001
  hubport: "127.0.0.1:40003"
`

const configFilePath = "./config.yaml"

func TestConfig(t *testing.T) {
	CreateHubConfigFile()
	defer RemoveConfigFile()

	hubCfg = nil
	initFlags()
	loadConfigs()

	if GetServer() != viper.GetString(confServer) {
		t.Errorf("get server error")
	}
	if GetPort() != viper.GetString(confPort) {
		t.Errorf("get port error")
	}
	saveConfigs()
	GetLogPath()
}

func CreateHubConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(Config), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}
