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
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// path
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/ras"
	strSysConf   = "/etc/attestation/ras"
	// config file name
	confName = "config"
	confExt  = "yaml"
	// logger
	logPath = "log.path"
	// rahub config key
	confServer = "hubconfig.server"
	confPort   = "hubconfig.port"
	// ras server listen ip:port
	lflagServer = "server"
	sflagServer = "s"
	helpServer  = "ras serves at IP:PORT"
	// rahub listen port
	lflagPort = "port"
	sflagPort = "p"
	helpPort  = "rahub listens at [IP]:PORT"
	// version output
	lflagVersion = "version"
	sflagVersion = "V"
	helpVersion  = "show version number and quit"
	// verbose output
	lflagVerbose = "verbose"
	sflagVerbose = "v"
	helpVerbose  = "show running debug information"
)

type (
	hubConfig struct {
		// logger path
		logPath string
		// rahub
		server string
		port   string
	}
)

var (
	defaultPaths = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	hubCfg      *hubConfig
	server      *string = nil
	port        *string = nil
	versionFlag *bool   = nil
	verboseFlag *bool   = nil
)

// initFlags inits the rahub whole command flags.
func initFlags() {
	server = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	port = pflag.StringP(lflagPort, sflagPort, "", helpPort)
	versionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	verboseFlag = pflag.BoolP(lflagVerbose, sflagVerbose, false, helpVerbose)
	pflag.Parse()
}

// getConfigs gets all config from config.yaml file.
func getConfigs() {
	if hubCfg == nil {
		return
	}
	hubCfg.server = viper.GetString(confServer)
	hubCfg.port = viper.GetString(confPort)
}

// loadConfigs searches and loads config from config.yaml file.
func loadConfigs() {
	if hubCfg != nil {
		return
	}
	// set default values
	hubCfg = &hubConfig{}
	// set config.yaml loading name and path
	viper.SetConfigName(confName)
	viper.SetConfigType(confExt)
	for _, s := range defaultPaths {
		viper.AddConfigPath(s)
	}
	err := viper.ReadInConfig()
	if err != nil {
		//fmt.Printf("read config file error: %v\n", err)
		return
	}
	getConfigs()
}

// saveConfigs saves all config variables to the config.yaml file.
func saveConfigs() {
	if hubCfg == nil {
		return
	}
	viper.Set(logPath, hubCfg.logPath)
	viper.Set(confServer, hubCfg.server)
	viper.Set(confPort, hubCfg.port)
	err := viper.WriteConfig()
	if err != nil {
		_ = viper.SafeWriteConfig()
	}
}

// GetLogPath returns the logger path configuration.
func GetLogPath() string {
	if hubCfg == nil {
		return ""
	}
	return hubCfg.logPath
}

// GetServer returns the ras server listening ip:port configuration.
func GetServer() string {
	if hubCfg == nil {
		return ""
	}
	return hubCfg.server
}

// GetPort returns the rahub listening ip:port configuration.
func GetPort() string {
	if hubCfg == nil {
		return ""
	}
	return hubCfg.port
}
