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

var defaultConfigPath = []string{
	".",
	"./config",
	"../config",
	"$HOME/.config/attestation",
	"/usr/lib/attestation",
	"/etc/attestation",
}

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

var cfg *config

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

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	for _, s := range defaultConfigPath {
		viper.AddConfigPath(s)
	}

	err := viper.ReadInConfig()
	if err == nil {
		cfg = &config{}
		if strings.ToLower(viper.GetString("conftype")) == "server" {
			cfg.isServer = true
		} else {
			cfg.isServer = false
		}
		if cfg.isServer {
			var mRules []entity.ManifestRule
			mrs, ok := viper.Get("rasConfig.basevalue-extract-rules.manifest").([]interface{})
			if ok {
				for _, mr := range mrs {
					var mRule entity.ManifestRule
					if m, ok := mr.(map[interface{}]interface{}); ok {
						for k, v := range m {
							if ks, ok := k.(string); ok {
								if ks == "type" {
									if vs, ok := v.(string); ok {
										mRule.MType = vs
									}
								}
								if ks == "name" {
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
			cfg.dbConfig.host = viper.GetString("database.host")
			cfg.dbConfig.dbName = viper.GetString("database.dbname")
			cfg.dbConfig.user = viper.GetString("database.user")
			cfg.dbConfig.password = viper.GetString("database.password")
			cfg.dbConfig.port = viper.GetInt("database.port")
			cfg.rasConfig.mgrStrategy = viper.GetString("rasConfig.mgrStrategy")
			cfg.rasConfig.changeTime = viper.GetTime("rasConfig.changeTime")
			cfg.rasConfig.extractRules.PcrRule.PcrSelection = viper.GetIntSlice("rasConfig.basevalue-extract-rules.pcrinfo.pcrselection")
			cfg.rasConfig.extractRules.ManifestRules = mRules
			cfg.racConfig.hbDuration = viper.GetDuration("racConfig.hbDuration")
			cfg.racConfig.trustDuration = viper.GetDuration("racConfig.trustDuration")
		} else {
			cfg.racConfig.hbDuration = viper.GetDuration("racConfig.hbDuration")
			cfg.racConfig.trustDuration = viper.GetDuration("racConfig.trustDuration")
			cfg.racConfig.clientId = viper.GetInt64("racConfig.clientId")
			cfg.racConfig.password = viper.GetString("racConfig.password")
		}
		return cfg
	}

	if cfg == nil {
		cfg = &config{
			isServer: false,
			dbConfig: dbConfig{
				host:     "localhost",
				dbName:   "test",
				user:     "",
				password: "",
				port:     5432,
			},
			rasConfig: rasConfig{
				mgrStrategy: "auto",
				changeTime:  time.Now(),
				extractRules: entity.ExtractRules{
					PcrRule: entity.PcrRule{
						PcrSelection: []int{1},
					},
					ManifestRules: []entity.ManifestRule{
						0: {
							MType: "bios",
							Name:  []string{""},
						},
						1: {
							MType: "ima",
							Name:  []string{""},
						},
					},
				},
			},
			racConfig: racConfig{
				hbDuration:    10 * time.Second,
				trustDuration: 120 * time.Second,
				clientId:      -1,
				password:      "",
			},
		}
	}

	return cfg
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if cfg != nil {
		if cfg.isServer {
			viper.Set("conftype", "server")
			viper.Set("database.host", cfg.dbConfig.host)
			viper.Set("database.dbname", cfg.dbConfig.dbName)
			viper.Set("database.user", cfg.dbConfig.user)
			viper.Set("database.password", cfg.dbConfig.password)
			viper.Set("database.port", cfg.dbConfig.port)
			viper.Set("rasConfig.mgrStrategy", cfg.rasConfig.mgrStrategy)
			viper.Set("rasConfig.changeTime", cfg.rasConfig.changeTime)
			// store common configuration for all client
			viper.Set("racConfig.hbDuration", cfg.racConfig.hbDuration)
			viper.Set("racConfig.trustDuration", cfg.racConfig.trustDuration)
		} else {
			viper.Set("conftype", "client")
			// store common part
			viper.Set("racConfig.hbDuration", cfg.racConfig.hbDuration)
			viper.Set("racConfig.trustDuration", cfg.racConfig.trustDuration)
			// store special configuration for this client
			viper.Set("racConfig.clientId", cfg.racConfig.clientId)
			viper.Set("racConfig.password", cfg.racConfig.password)
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
