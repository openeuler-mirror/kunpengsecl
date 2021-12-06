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
	RasPort               = "rasconfig.port" // server listen port
	RasPortLongFlag       = "port"
	RasPortShortFlag      = "p"
	RasRestPort           = "rasconfig.rest" // rest listen port
	RasRestPortLongFlag   = "rest"
	RasRestPortShortFlag  = "r"
	RasMgrStrategy        = "rasconfig.mgrstrategy"
	RasAutoStrategy       = "auto"
	RasAutoUpdateStrategy = "auto-update"
	RasChangeTime         = "rasconfig.changetime"
	RasExtRules           = "rasconfig.basevalue-extract-rules"
	RasAutoUpdateConfig   = "rasconfig.auto-update-config"
	// RAC
	RacServer                = "racconfig.server" // client connect to server
	RacServerLongFlag        = "server"
	RacServerShortFlag       = "s"
	RacTestModeLongFlag      = "test"
	RacTestModeShortFlag     = "t"
	RacHbDuration            = "racconfig.hbduration"
	RacDefaultHbDuration     = 10 // seconds
	RacTrustDuration         = "racconfig.trustduration"
	RacDefaultTrustDuration  = 120 // seconds
	RacClientId              = "racconfig.clientid"
	RacNullClientId          = -1
	RacPassword              = "racconfig.password"
	RacDefaultPassword       = ""
	RacDigestAlgorithm       = "racconfig.digestalgorithm"
	RacDigestAlgorithmSHA256 = "sha256"
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
	cfg *config
	// for RAS command line parameters
	servPort *string = nil
	restPort *string = nil
	// for RAC command line parameters
	racServer   *string = nil
	racTestMode *bool   = nil
	// for HUB command line parameters
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
		servPort         string
		restPort         string
		mgrStrategy      string
		changeTime       time.Time
		extractRules     entity.ExtractRules
		autoUpdateConfig entity.AutoUpdateConfig
	}
	racConfig struct {
		server          string
		testMode        bool
		hbDuration      time.Duration // heartbeat duration
		trustDuration   time.Duration // trust state duration
		clientId        int64
		password        string
		digestAlgorithm string
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
}

// InitRacFlags sets the rac client whole command flags.
func InitRacFlags() {
	racServer = pflag.StringP(RacServerLongFlag, RacServerShortFlag, "", "connect attestation server at IP:PORT")
	racTestMode = pflag.BoolP(RacTestModeLongFlag, RacTestModeShortFlag, false, "run in test mode[true] or not[false/default]")
}

// InitRacFlags sets the rac client whole command flags.
func InitHubFlags() {
	hubServer = pflag.StringP(HubServerLongFlag, HubServerShortFlag, "", "connect attestation server at IP:PORT")
	hubPort = pflag.StringP(HubPortLongFlag, HubPortShortFlag, "", "hub listen at [IP]:PORT")
}

func getServerConf(c *config) {
	if c == nil {
		return
	}
	c.dbConfig.host = viper.GetString(DbHost)
	c.dbConfig.dbName = viper.GetString(DbName)
	c.dbConfig.port = viper.GetInt(DbPort)
	c.dbConfig.user = viper.GetString(DbUser)
	c.dbConfig.password = viper.GetString(DbPassword)
	c.rasConfig.servPort = viper.GetString(RasPort)
	c.rasConfig.restPort = viper.GetString(RasRestPort)
	c.rasConfig.mgrStrategy = viper.GetString(RasMgrStrategy)
	c.rasConfig.changeTime = viper.GetTime(RasChangeTime)
	var ers entity.ExtractRules
	if viper.UnmarshalKey(RasExtRules, &ers) == nil {
		c.rasConfig.extractRules = ers
	} else {
		c.rasConfig.extractRules = entity.ExtractRules{}
	}
	var auc entity.AutoUpdateConfig
	if viper.UnmarshalKey(RasAutoUpdateConfig, &auc) == nil {
		c.rasConfig.autoUpdateConfig = auc
	} else {
		c.rasConfig.autoUpdateConfig = entity.AutoUpdateConfig{}
	}
	c.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
	c.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
	c.racConfig.digestAlgorithm = viper.GetString(RacDigestAlgorithm)
	// set command line input
	if servPort != nil && *servPort != "" {
		c.rasConfig.servPort = *servPort
	}
	if restPort != nil && *restPort != "" {
		c.rasConfig.restPort = *restPort
	}
}

func getClientConf(c *config) {
	if c == nil {
		return
	}
	c.racConfig.server = viper.GetString(RacServer)
	c.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
	c.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
	c.racConfig.clientId = viper.GetInt64(RacClientId)
	c.racConfig.password = viper.GetString(RacPassword)
	c.racConfig.digestAlgorithm = viper.GetString(RacDigestAlgorithm)
	// set command line input
	if racServer != nil && *racServer != "" {
		c.racConfig.server = *racServer
	}
	if racTestMode != nil {
		c.racConfig.testMode = *racTestMode
	}
}

func getHubConf(c *config) {
	if c == nil {
		return
	}
	c.hubConfig.server = viper.GetString(HubServer)
	c.hubConfig.hubPort = viper.GetString(HubPort)
	// set command line input
	if hubServer != nil && *hubServer != "" {
		c.hubConfig.server = *hubServer
	}
	if hubPort != nil && *hubPort != "" {
		c.hubConfig.hubPort = *hubPort
	}
}

/*
GetDefault returns the global default config object.
It searches the defaultConfigPath to find the first matched config.yaml.
if it doesn't find any one, it returns the default values by code.
Notice:
  server must has a config.yaml to give the configuration.
  client may not have one.
*/
func GetDefault(cfType string) *config {
	if cfg != nil {
		return cfg
	}

	viper.SetConfigName(ConfName)
	viper.SetConfigType(ConfExt)
	for _, s := range defaultConfigPath {
		viper.AddConfigPath(s)
	}

	// set default configuration for different app.
	cf := strings.ToLower(cfType)
	switch cf {
	case ConfServer:
	case ConfClient:
		viper.SetDefault(RacHbDuration, RacDefaultHbDuration)
		viper.SetDefault(RacTrustDuration, RacDefaultTrustDuration)
		viper.SetDefault(RacClientId, RacNullClientId)
		viper.SetDefault(RacPassword, RacDefaultPassword)
		viper.SetDefault(RacDigestAlgorithm, RacDigestAlgorithmSHA256)
	case ConfHub:
	}

	err := viper.ReadInConfig()
	if err != nil {
		fmt.Printf("read config file error: %v\n", err)
	}

	cfg = &config{}
	cfg.confType = cf
	switch cfg.confType {
	case ConfServer:
		getServerConf(cfg)
	case ConfClient:
		getClientConf(cfg)
	case ConfHub:
		getHubConf(cfg)
	}
	return cfg
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if cfg != nil {
		switch cfg.confType {
		case ConfServer:
			viper.Set(DbHost, cfg.dbConfig.host)
			viper.Set(DbName, cfg.dbConfig.dbName)
			viper.Set(DbPort, cfg.dbConfig.port)
			viper.Set(DbUser, cfg.dbConfig.user)
			viper.Set(DbPassword, cfg.dbConfig.password)
			viper.Set(RasPort, cfg.rasConfig.servPort)
			viper.Set(RasRestPort, cfg.rasConfig.restPort)
			viper.Set(RasMgrStrategy, cfg.rasConfig.mgrStrategy)
			viper.Set(RasChangeTime, cfg.rasConfig.changeTime)
			viper.Set(RasAutoUpdateConfig, cfg.rasConfig.autoUpdateConfig)
			// store common configuration for all client
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
			viper.Set(RacDigestAlgorithm, cfg.racConfig.digestAlgorithm)
		case ConfClient:
			// store common part
			viper.Set(RacServer, cfg.racConfig.server)
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
			viper.Set(RacDigestAlgorithm, cfg.racConfig.digestAlgorithm)
			// store special configuration for this client
			viper.Set(RacClientId, cfg.racConfig.clientId)
			viper.Set(RacPassword, cfg.racConfig.password)
		case ConfHub:
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

func (c *config) GetServer() string {
	return c.racConfig.server
}

func (c *config) GetTestMode() bool {
	return c.racConfig.testMode
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

func (c *config) SetAutoUpdateConfig(a entity.AutoUpdateConfig) {
	c.rasConfig.autoUpdateConfig = a
}

func (c *config) GetAutoUpdateConfig() entity.AutoUpdateConfig {
	return c.rasConfig.autoUpdateConfig
}

func (c *config) GetPort() string {
	return c.rasConfig.servPort
}

func (c *config) GetRestPort() string {
	return c.rasConfig.restPort
}

func (c *config) GetHubServer() string {
	return c.hubConfig.server
}

func (c *config) GetHubPort() string {
	return c.hubConfig.hubPort
}

func (c *config) GetDigestAlgorithm() string {
	return c.racConfig.digestAlgorithm
}

func (c *config) SetDigestAlgorithm(algorithm string) {
	c.racConfig.digestAlgorithm = algorithm
}
