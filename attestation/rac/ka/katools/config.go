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
	"time"

	"github.com/spf13/viper"
)

const (
	// path
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/rac"
	strSysConf   = "/etc/attestation/rac"
	// config file name
	confName = "config"
	confExt  = "yaml"
	// ka config key
	confKaPollDuration = "kaconfig.pollduration"
	confCKeyCert       = "kaconfig.ccFile" // ca cert
	confKKeyCert       = "kaconfig.kcFile"
	confKKeyFile       = "kaconfig.kKeyFile"
	confKtaPath        = "kaconfig.ktapath"
	nullString         = ""

	// default values
	defaultDuration = time.Second
	keyExt          = ".key"
	crtExt          = ".crt"
	caCert          = "./cert/ca"
	ktaCert         = "./cert/kta"
	ktaKey          = "./cert/kta"
)

type (
	kaConfig struct {
		pollDuration time.Duration
		ccFile       string
		kcFile       string
		kKeyFile     string
		ktaPath      string
	}
)

var (
	defaultPaths = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	kaCfg *kaConfig
)

// loadConfigs searches and loads config from config.yaml file.
func loadConfigs() {
	if kaCfg != nil {
		return
	}
	// set default values
	kaCfg = &kaConfig{}
	kaCfg.pollDuration = viper.GetDuration(confKaPollDuration)
	kaCfg.ccFile = viper.GetString(confCKeyCert)
	kaCfg.kcFile = viper.GetString(confKKeyCert)
	kaCfg.kKeyFile = viper.GetString(confKKeyFile)
	kaCfg.ktaPath = viper.GetString(confKtaPath)
}

func getPollDuration() time.Duration {
	if kaCfg == nil {
		return 0
	}
	dur := kaCfg.pollDuration
	if kaCfg.pollDuration == 0 {
		dur = defaultDuration
	}
	return dur
}

func getCaCertFile() string {
	if kaCfg == nil {
		return nullString
	}
	if kaCfg.ccFile == nullString {
		kaCfg.ccFile = caCert + crtExt
	}
	return kaCfg.ccFile
}

func getKtaCertFile() string {
	if kaCfg == nil {
		return nullString
	}
	if kaCfg.kcFile == nullString {
		kaCfg.kcFile = ktaCert + crtExt
	}
	return kaCfg.kcFile
}

func getKtaKeyFile() string {
	if kaCfg == nil {
		return nullString
	}
	if kaCfg.kKeyFile == nullString {
		kaCfg.kKeyFile = ktaKey + crtExt
	}
	return kaCfg.kKeyFile
}
func getKtaPath() string {
	if kaCfg == nil {
		return nullString
	}
	return kaCfg.ktaPath
}
