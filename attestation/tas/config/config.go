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
Create: 2022-04-01
Description: Store TAS configurations
*/

package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// config path
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/tas"
	strSysConf   = "/etc/attestation/tas"
	// config file
	confName           = "config"
	confExt            = "yaml"
	confServPort       = "tasconfig.port"
	confRestPort       = "tasconfig.rest"
	confTASKeyCertFile = "tasconfig.akskeycertfile"
	confTASPrivKeyFile = "tasconfig.aksprivkeyfile"
	confHWITCACertFile = "tasconfig.huaweiitcafile"
	confDAAGrpPrivKeyX = "tasconfig.DAA_GRP_KEY_SK_X"
	confDAAGrpPrivKeyY = "tasconfig.DAA_GRP_KEY_SK_Y"
	confAuthKeyFile    = "tasconfig.authkeyfile"
	confBaseValue      = "tasconfig.basevalue"
	// cmd flag
	// token output
	lflagToken = "token"
	sflagToken = "T"
	helpToken  = "generate test token for rest api"
)

type (
	tasConfig struct {
		servPort       string
		restPort       string
		tasKeyCertFile string
		tasPrivKeyFile string
		hwItCACertFile string
		DAAGrpPrivKeyX string
		DAAGrpPrivKeyY string
		authKeyFile    string
		basevalue      string
	}
)

var (
	defaultPaths = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	tasCfg    *tasConfig
	ascert    *x509.Certificate
	asprivkey *rsa.PrivateKey
	hwcert    *x509.Certificate
	// TokenFlag means token flag
	TokenFlag *bool
)

// InitFlags inits the tas server command flags.
func InitFlags() {
	TokenFlag = pflag.BoolP(lflagToken, sflagToken, false, helpToken)
	pflag.Parse()
}

// LoadConfigs searches and loads config from config.yaml file.
func LoadConfigs() {
	log.Print("Load TAS configs...")
	if tasCfg != nil {
		return
	}
	tasCfg = &tasConfig{}
	viper.SetConfigName(confName)
	viper.SetConfigType(confExt)
	for _, s := range defaultPaths {
		viper.AddConfigPath(s)
	}
	err := viper.ReadInConfig()
	if err != nil {
		return
	}

	tasCfg.servPort = viper.GetString(confServPort)
	tasCfg.restPort = viper.GetString(confRestPort)
	tasCfg.tasKeyCertFile = viper.GetString(confTASKeyCertFile)
	tasCfg.tasPrivKeyFile = viper.GetString(confTASPrivKeyFile)
	tasCfg.hwItCACertFile = viper.GetString(confHWITCACertFile)
	tasCfg.DAAGrpPrivKeyX = viper.GetString(confDAAGrpPrivKeyX)
	tasCfg.DAAGrpPrivKeyY = viper.GetString(confDAAGrpPrivKeyY)
	tasCfg.authKeyFile = viper.GetString(confAuthKeyFile)
	tasCfg.basevalue = viper.GetString(confBaseValue)
}

// InitializeAS initializes tas server by parsing as cert,
// parsing as private key and parsing hw it ca cert.
func InitializeAS() error {
	// parse as cert
	certfile := GetASCertFile()
	ascertbyte, err := ioutil.ReadFile(certfile)
	if err != nil {
		return err
	}
	ascertBlock, _ := pem.Decode(ascertbyte)
	ascert, err = x509.ParseCertificate(ascertBlock.Bytes)
	if err != nil {
		return err
	}
	// parse as private key
	askeyfile := GetASKeyFile()
	askeybyte, err := ioutil.ReadFile(askeyfile)
	if err != nil {
		return err
	}
	askeyBlock, _ := pem.Decode(askeybyte)
	asprivkey, err = x509.ParsePKCS1PrivateKey(askeyBlock.Bytes)
	if err != nil {
		return err
	}
	// parse hw it ca cert
	hwcafile := GetHWCertFile()
	hwcabyte, err := ioutil.ReadFile(hwcafile)
	if err != nil {
		return err
	}
	hwcaBlock, _ := pem.Decode(hwcabyte)
	hwcert, err = x509.ParseCertificate(hwcaBlock.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// GetConfigs gets all config from config.yaml file.
func GetConfigs() *tasConfig {
	return tasCfg
}

// GetServerPort returns the tas service ip:port configuration.
func GetServerPort() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.servPort
}

// GetRestPort returns the tas restful api interface ip:port configuration.
func GetRestPort() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.restPort
}

// GetASCertFile returns the tas service key cert file configuration.
func GetASCertFile() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.tasKeyCertFile
}

// GetASKeyFile returns the tas service private key file configuration.
func GetASKeyFile() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.tasPrivKeyFile
}

// GetHWCertFile returns the tas service hua wei IT ca cert file configuration.
func GetHWCertFile() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.hwItCACertFile
}

// GetASCert returns the as cert file in *x509.Certificate format.
func GetASCert() *x509.Certificate {
	return ascert
}

// GetASPrivKey returns the as private key in *rsa.PrivateKey format.
func GetASPrivKey() *rsa.PrivateKey {
	return asprivkey
}

// GetHWCert returns hua wei cert.
func GetHWCert() *x509.Certificate {
	return hwcert
}

// GetDAAGrpPrivKey returns the tas service daa crp private key x
// and private key y configuration.
func GetDAAGrpPrivKey() (string, string) {
	return tasCfg.DAAGrpPrivKeyX, tasCfg.DAAGrpPrivKeyY
}

// GetAuthKeyFile returns the tas service auth key file configuration.
func GetAuthKeyFile() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.authKeyFile
}

// GetBaseValue returns the tas service basevalue configuration.
func GetBaseValue() string {
	if tasCfg == nil {
		return ""
	}
	return tasCfg.basevalue
}

// SetBaseValue sets the tas service basevalue configuration.
func SetBaseValue(s string) {
	if tasCfg == nil {
		return
	}
	tasCfg.basevalue = s
}
