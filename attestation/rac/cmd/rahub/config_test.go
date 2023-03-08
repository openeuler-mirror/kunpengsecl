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
	err := ioutil.WriteFile(configFilePath, []byte(Config), 0644)
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
