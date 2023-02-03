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

package katools

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/spf13/viper"
)

const (
	configFilePath = "./config.yaml"
	clientKaConfig = `
kaconfig:
  pollduration: 3s
  ccFile: ./cert/ca.crt
  kcFile: ./cert/kta.crt
  kKeyFile: ./cert/kta.key
  ktapath: /root/data/bbb2d138-ee21-43af-8796-40c20d7b45fa.sec
`
)

func CreateClientConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(clientKaConfig), 0644)
}
func RemoveConfigFile() {
	os.Remove(configFilePath)
}
func PrepareConfig() {
	viper.SetConfigName(confName)
	viper.SetConfigType(confExt)
	for _, s := range defaultPaths {
		viper.AddConfigPath(s)
	}
	err := viper.ReadInConfig()
	if err != nil {
		// fmt.Printf("read config file error: %v\n", err)
		return
	}
}

func TestGetPollDuration(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	PrepareConfig()
	loadConfigs()
	polldur := getPollDuration()
	if polldur == 0 {
		t.Errorf("Get poll duration error\n")
	}
	t.Logf("polldur=%v\n", polldur)
}

func TestGetCaCertFile(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	PrepareConfig()
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
	PrepareConfig()
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
	PrepareConfig()
	loadConfigs()
	ktaKey := getKtaKeyFile()
	if ktaKey == nullString {
		t.Errorf("Get kta key file error\n")
	}
	t.Logf("ktaCert=%v\n", ktaKey)
}
func TestGetKtaPath(t *testing.T) {
	CreateClientConfigFile()
	defer RemoveConfigFile()
	PrepareConfig()
	loadConfigs()
	ktaPath := getKtaPath()
	if ktaPath == nullString {
		t.Errorf("Get kta path error\n")
	}
	t.Logf("ktaPath=%v\n", ktaPath)
}
