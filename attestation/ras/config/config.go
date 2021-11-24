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
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/spf13/viper"
)

const (
	// normal
	ConfName   = "config"
	ConfExt    = "yaml"
	ConfType   = "conftype"
	ConfServer = "server"
	ConfClient = "client"
	// database
	DbHost        = "database.host"
	DbName        = "database.dbname"
	DbUser        = "database.user"
	DbPassword    = "database.password"
	DbPort        = "database.port"
	DbDefaultHost = "localhost"
	DbDefaultName = "test"
	DbDefaultNull = ""
	DbDefaultPort = 5432
	// RAS
	RasMgrStrategy  = "rasConfig.mgrStrategy"
	RasAutoStrategy = "auto"
	RasChangeTime   = "rasConfig.changeTime"
	RasExtRules     = "rasConfig.basevalue-extract-rules.manifest"
	RasMfrTypeBios  = "bios"
	RasMfrTypeIma   = "ima"
	RasPcrSelection = "rasConfig.basevalue-extract-rules.pcrinfo.pcrselection"
	RasKsType       = "type"
	RasKsName       = "name"
	// RAC
	RacHbDuration           = "racConfig.hbDuration"
	RacDefaultHbDuration    = 10 // seconds
	RacTrustDuration        = "racConfig.trustDuration"
	RacDefaultTrustDuration = 120 // seconds
	RacClientId             = "racConfig.clientId"
	RacNullClientId         = -1
	RacPassword             = "racConfig.password"
	RacDefaultPassword      = ""
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
		mgrStrategy  string
		changeTime   time.Time
		extractRules entity.ExtractRules
	}
	racConfig struct {
		hbDuration    time.Duration // heartbeat duration
		trustDuration time.Duration // trust state duration
		clientId      int64
		password      string
	}
	config struct {
		isServer bool
		dbConfig
		rasConfig
		racConfig
	}
)

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

	err := viper.ReadInConfig()
	if err == nil {
		cfg = &config{}
		if strings.ToLower(viper.GetString(ConfType)) == ConfServer {
			cfg.isServer = true
		} else {
			cfg.isServer = false
		}
		if cfg.isServer {
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
			cfg.dbConfig.user = viper.GetString(DbUser)
			cfg.dbConfig.password = viper.GetString(DbPassword)
			cfg.dbConfig.port = viper.GetInt(DbPort)
			cfg.rasConfig.mgrStrategy = viper.GetString(RasMgrStrategy)
			cfg.rasConfig.changeTime = viper.GetTime(RasChangeTime)
			cfg.rasConfig.extractRules.PcrRule.PcrSelection = viper.GetIntSlice(RasPcrSelection)
			cfg.rasConfig.extractRules.ManifestRules = mRules
			cfg.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
			cfg.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
		} else {
			cfg.racConfig.hbDuration = viper.GetDuration(RacHbDuration)
			cfg.racConfig.trustDuration = viper.GetDuration(RacTrustDuration)
			cfg.racConfig.clientId = viper.GetInt64(RacClientId)
			cfg.racConfig.password = viper.GetString(RacPassword)
		}
		return cfg
	}

	if cfg == nil {
		cfg = &config{
			isServer: false,
			dbConfig: dbConfig{
				host:     DbDefaultHost,
				dbName:   DbDefaultName,
				user:     DbDefaultNull,
				password: DbDefaultNull,
				port:     DbDefaultPort,
			},
			rasConfig: rasConfig{
				mgrStrategy: RasAutoStrategy,
				changeTime:  time.Now(),
				extractRules: entity.ExtractRules{
					PcrRule: entity.PcrRule{
						PcrSelection: []int{1},
					},
					ManifestRules: []entity.ManifestRule{
						0: {
							MType: RasMfrTypeBios,
							Name:  []string{""},
						},
						1: {
							MType: RasMfrTypeIma,
							Name:  []string{""},
						},
					},
				},
			},
			racConfig: racConfig{
				hbDuration:    RacDefaultHbDuration * time.Second,
				trustDuration: RacDefaultTrustDuration * time.Second,
				clientId:      RacNullClientId,
				password:      RacDefaultPassword,
			},
		}
	}

	return cfg
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if cfg != nil {
		if cfg.isServer {
			viper.Set(ConfType, ConfServer)
			viper.Set(DbHost, cfg.dbConfig.host)
			viper.Set(DbName, cfg.dbConfig.dbName)
			viper.Set(DbUser, cfg.dbConfig.user)
			viper.Set(DbPassword, cfg.dbConfig.password)
			viper.Set(DbPort, cfg.dbConfig.port)
			viper.Set(RasMgrStrategy, cfg.rasConfig.mgrStrategy)
			viper.Set(RasChangeTime, cfg.rasConfig.changeTime)
			// store common configuration for all client
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
		} else {
			viper.Set(ConfType, ConfClient)
			// store common part
			viper.Set(RacHbDuration, cfg.racConfig.hbDuration)
			viper.Set(RacTrustDuration, cfg.racConfig.trustDuration)
			// store special configuration for this client
			viper.Set(RacClientId, cfg.racConfig.clientId)
			viper.Set(RacPassword, cfg.racConfig.password)
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

func (c *config) GetPort() int {
	return c.dbConfig.port
}

func (c *config) SetPort(port int) {
	c.dbConfig.port = port
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
