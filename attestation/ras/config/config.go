/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-09-17
Description: Store RAS and RAC configurations.
*/

package config

import (
	"fmt"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// normal
	ConfName   = "config"
	ConfExt    = "yaml"
	ConfType   = "conftype"
	ConfServer = "server"
	ConfClient = "client"
	ConfHub    = "hub"
	// database
	DbHost     = "database.host"
	DbName     = "database.dbname"
	DbPort     = "database.port"
	DbUser     = "database.user"
	DbPassword = "database.password"
	// RAS
	RasPort              = "rasconfig.port" // server listen port
	RasPortLongFlag      = "port"
	RasPortShortFlag     = "p"
	RasRestPort          = "rasconfig.rest" // rest listen port
	RasRestPortLongFlag  = "rest"
	RasRestPortShortFlag = "r"
	RasMgrStrategy       = "rasconfig.mgrstrategy"
	RasAutoStrategy      = "auto"
	RasChangeTime        = "rasconfig.changetime"
	RasExtRules          = "rasconfig.basevalue-extract-rules.manifest"
	RasMfrTypeBios       = "bios"
	RasMfrTypeIma        = "ima"
	RasPcrSelection      = "rasconfig.basevalue-extract-rules.pcrinfo.pcrselection"
	RasKsType            = "type"
	RasKsName            = "name"
	// RAC
	RacServer               = "racconfig.server" // client connect to server
	RacServerLongFlag       = "server"
	RacServerShortFlag      = "s"
	RacHbDuration           = "racconfig.hbduration"
	RacDefaultHbDuration    = 10 // seconds
	RacTrustDuration        = "racconfig.trustduration"
	RacDefaultTrustDuration = 120 // seconds
	RacClientId             = "racconfig.clientid"
	RacNullClientId         = -1
	RacPassword             = "racconfig.password"
	RacDefaultPassword      = ""
	// Hub
	HubServer          = "hubconfig.server"
	HubServerLongFlag  = "server"
	HubServerShortFlag = "s"
	HubPort            = "hubconfig.hubport"
	HubPortLongFlag    = "hubport"
	HubPortShortFlag   = "p"
)

var (
	defaultConfigPath = []string{
		".",
		"./config",
		"../config",
		"$HOME/.config/attestation",
		"/usr/lib/attestation",
		"/etc/attestation",
	}
	cfg       *config
	servPort  *string = nil
	restPort  *string = nil
	racServer *string = nil
	hubServer *string = nil
	hubPort   *string = nil
)

type (
	dbConfig struct {
		host     string
		dbName   string
		user     string
		password string
		port     int
	}
	rasConfig struct {
		servPort     string
		restPort     string
		mgrStrategy  string
		changeTime   time.Time
		extractRules entity.ExtractRules
	}
	racConfig struct {
		server        string
		hbDuration    time.Duration // heartbeat duration
		trustDuration time.Duration // trust state duration
		clientId      int64
		password      string
	}
	hubConfig struct {
		server  string
		hubPort string
	}
	config struct {
		confType string
		dbConfig
		rasConfig
		racConfig
		hubConfig
	}
)

// InitRasFlags sets the ras server whole command flags.
func InitRasFlags() {
	servPort = pflag.StringP(RasPortLongFlag, RasPortShortFlag, "", "this app service listen at [IP]:PORT")
	restPort = pflag.StringP(RasRestPortLongFlag, RasRestPortShortFlag, "", "this app rest interface listen at [IP]:PORT")
	viper.BindPFlags(pflag.CommandLine)
}

// InitRacFlags sets the rac client whole command flags.
func InitRacFlags() {
	racServer = pflag.StringP(RacServerLongFlag, RacServerShortFlag, "", "connect attestation server at IP:PORT")
	viper.BindPFlags(pflag.CommandLine)
}

// InitRacFlags sets the rac client whole command flags.
func InitHubFlags() {
	hubServer = pflag.StringP(HubServerLongFlag, HubServerShortFlag, "", "connect attestation server at IP:PORT")
	hubPort = pflag.StringP(HubPortLongFlag, HubPortShortFlag, "", "hub listen at [IP]:PORT")
	viper.BindPFlags(pflag.CommandLine)
}

/*
GetDefault returns the global default config object.
It searches the defaultConfigPath to find the first matched config.yaml.
if it doesn't find any one, it returns the default values by code.
Notice:
  server must has a config.yaml to give the configuration.
  client may not have one.
*/
func GetDefault() *config {
	if cfg != nil {
		return cfg
	}

	viper.SetConfigName(ConfName)
	viper.SetConfigType(ConfExt)
	for _, s := range defaultConfigPath {
		viper.AddConfigPath(s)
	}

	// set client default configuration into viper
	viper.SetDefault(ConfType, ConfClient)
	viper.SetDefault(RacHbDuration, RacDefaultHbDuration)
	viper.SetDefault(RacTrustDuration, RacDefaultTrustDuration)
	viper.SetDefault(RacClientId, RacNullClientId)
	viper.SetDefault(RacPassword, RacDefaultPassword)

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("read config file error: %v\n", err)
	}

	cfg = &config{}
	cfg.confType = strings.ToLower(viper.GetString(ConfType))
	switch cfg.confType {
	case ConfServer:
		var mRules []entity.ManifestRule
		mrs, ok := viper.Get(RasExtRules).([]interface{})
		if ok {
			for _, mr := range mrs {
				var mRule entity.ManifestRule
				if m, ok := mr.(map[interface{}]interface{}); ok {
					for k, v := range m {
						if ks, ok := k.(string); ok {
							if ks == RasKsType {
								if vs, ok := v.(string); ok {
									mRule.MType = vs
								}
							}
							if ks == RasKsName {
								var names []string
								if ns, ok := v.([]interface{}); ok {
									for _, n := range ns {
										names = append(names, n.(string))
									}
									mRule.Name = names
								}
							}
						}
					}
					mRules = append(mRules, mRule)
				}
			}
		}
		cfg.dbConfig.host = viper.GetString(DbHost)
		cfg.dbConfig.dbName = viper.GetString(DbName)
		cfg.dbConfig.port = viper.GetInt(DbPort)
		cfg.dbConfig.user = viper.GetString(DbUser)
		cfg.dbConfig.password = viper.GetString(DbPassword)
		cfg.rasConfig.servPort = viper.GetString(RasPort)
		cfg.rasConfig.restPort = viper.GetString(RasRestPort)
		cfg.rasConfig.mgrStrategy = viper.GetString(RasMgrStrategy)
		cfg.rasConfig.changeTime = viper.GetTime(RasChangeTime)
		cfg.rasConfig.extractRules.PcrRule.PcrSelection = viper.GetIntSlice(RasPcrSelection)
		cfg.rasConfig.extractRules.ManifestRules = mRules
		cfg.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
		cfg.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
		// set command line input
		if servPort != nil && *servPort != "" {
			cfg.rasConfig.servPort = *servPort
		}
		if restPort != nil && *restPort != "" {
			cfg.rasConfig.restPort = *restPort
		}
	case ConfClient:
		cfg.racConfig.server = viper.GetString(RacServer)
		cfg.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
		cfg.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
		cfg.racConfig.clientId = viper.GetInt64(RacClientId)
		cfg.racConfig.password = viper.GetString(RacPassword)
		// set command line input
		if racServer != nil && *racServer != "" {
			cfg.racConfig.server = *racServer
		}
	case ConfHub:
		cfg.hubConfig.server = viper.GetString(HubServer)
		cfg.hubConfig.hubPort = viper.GetString(HubPort)
		// set command line input
		if hubServer != nil && *hubServer != "" {
			cfg.hubConfig.server = *hubServer
		}
		if hubPort != nil && *hubPort != "" {
			cfg.hubConfig.hubPort = *hubPort
		}
	}
	return cfg
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if cfg != nil {
		switch cfg.confType {
		case ConfServer:
			viper.Set(ConfType, ConfServer)
			viper.Set(DbHost, cfg.dbConfig.host)
			viper.Set(DbName, cfg.dbConfig.dbName)
			viper.Set(DbPort, cfg.dbConfig.port)
			viper.Set(DbUser, cfg.dbConfig.user)
			viper.Set(DbPassword, cfg.dbConfig.password)
			viper.Set(RasPort, cfg.rasConfig.servPort)
			viper.Set(RasRestPort, cfg.rasConfig.restPort)
			viper.Set(RasMgrStrategy, cfg.rasConfig.mgrStrategy)
			viper.Set(RasChangeTime, cfg.rasConfig.changeTime)
			// store common configuration for all client
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
		case ConfClient:
			viper.Set(ConfType, ConfClient)
			// store common part
			viper.Set(RacServer, cfg.racConfig.server)
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
			// store special configuration for this client
			viper.Set(RacClientId, cfg.racConfig.clientId)
			viper.Set(RacPassword, cfg.racConfig.password)
		case ConfHub:
			viper.Set(ConfType, ConfHub)
			viper.Set(HubServer, cfg.hubConfig.server)
			viper.Set(HubPort, cfg.hubConfig.hubPort)
		}
		err := viper.WriteConfig()
		if err != nil {
			_ = viper.SafeWriteConfig()
		}
	}
}

func (c *config) GetHost() string {
	return c.dbConfig.host
}

func (c *config) SetHost(host string) {
	c.dbConfig.host = host
}

func (c *config) GetDBName() string {
	return c.dbConfig.dbName
}

func (c *config) SetDBName(dbName string) {
	c.dbConfig.dbName = dbName
}

func (c *config) GetDBPort() int {
	return c.dbConfig.port
}

func (c *config) SetDBPort(port int) {
	c.dbConfig.port = port
}

func (c *config) GetUser() string {
	return c.dbConfig.user
}

func (c *config) SetUser(user string) {
	c.dbConfig.user = user
}

func (c *config) GetPassword() string {
	return c.dbConfig.password
}

func (c *config) SetPassword(password string) {
	c.dbConfig.password = password
}

func (c *config) GetTrustDuration() time.Duration {
	return c.racConfig.trustDuration
}

func (c *config) SetTrustDuration(d time.Duration) {
	c.racConfig.trustDuration = d
}

func (c *config) GetHBDuration() time.Duration {
	return c.racConfig.hbDuration
}

func (c *config) SetHBDuration(d time.Duration) {
	c.racConfig.hbDuration = d
}

func (c *config) GetClientId() int64 {
	return c.racConfig.clientId
}

func (c *config) SetClientId(id int64) {
	c.racConfig.clientId = id
}

func (c *config) GetMgrStrategy() string {
	return c.rasConfig.mgrStrategy
}

func (c *config) SetMgrStrategy(s string) {
	c.rasConfig.mgrStrategy = s
	c.rasConfig.changeTime = time.Now()
}

func (c *config) GetChangeTime() time.Time {
	return c.rasConfig.changeTime
}

func (c *config) SetExtractRules(e entity.ExtractRules) {
	c.rasConfig.extractRules = e
}

func (c *config) GetExtractRules() entity.ExtractRules {
	return c.rasConfig.extractRules
}

func (c *config) GetPort() string {
	return c.rasConfig.servPort
}

func (c *config) GetRestPort() string {
	return c.rasConfig.restPort
}

func (c *config) GetServer() string {
	return c.racConfig.server
}

func (c *config) GetHubServer() string {
	return c.hubConfig.server
}

func (c *config) GetHubPort() string {
	return c.hubConfig.hubPort
}
