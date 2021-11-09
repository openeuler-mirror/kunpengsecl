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
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/spf13/viper"
)

var defaultConfigPath = []string{
	".",
	"./config",
	"$HOME/.config/attestation",
	"/usr/lib/attestation",
	"/etc/attestation",
	"../config",
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
		cpassword     string
	}
	config struct {
		dbConfig
		rasConfig
		racConfig
	}
)

var cfg *config
var racCfg *racConfig

/*
	GetDefault returns the global default config object.
	It searches the defaultConfigPath to find the first matched config.yaml.
	if it doesn't find any one, it returns the default values by code.
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

	if err == nil {
		cfg = &config{
			dbConfig: dbConfig{
				host:     viper.GetString("database.host"),
				dbName:   viper.GetString("database.dbname"),
				user:     viper.GetString("database.user"),
				password: viper.GetString("database.password"),
				port:     viper.GetInt("database.port"),
			},
			rasConfig: rasConfig{
				mgrStrategy: viper.GetString("rasConfig.mgrStrategy"),
				changeTime:  viper.GetTime("rasConfig.changeTime"),
				extractRules: entity.ExtractRules{
					PcrRule: entity.PcrRule{
						PcrSelection: viper.GetIntSlice("rasConfig.basevalue-extract-rules.pcrinfo.pcrselection"),
					},
					ManifestRules: mRules,
				},
			},
			racConfig: racConfig{
				hbDuration:    viper.GetDuration("racConfig.hbDuration"),
				trustDuration: viper.GetDuration("racConfig.trustDuration"),
				clientId:      viper.GetInt64("racConfig.clientId"),
				cpassword:     viper.GetString("racConfig.cpassword"),
			},
		}
		return cfg
	}

	if cfg == nil {
		cfg = &config{
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
				cpassword:     "",
			},
		}
	}

	racCfg = &cfg.racConfig
	return cfg
}

func GetDefaultRac() *racConfig {
	if racCfg != nil {
		return racCfg
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	for _, s := range defaultConfigPath {
		viper.AddConfigPath(s)
	}

	err := viper.ReadInConfig()
	if err == nil {
		racCfg = &racConfig{
			hbDuration:    viper.GetDuration("racConfig.hbDuration"),
			trustDuration: viper.GetDuration("racConfig.trustDuration"),
			clientId:      viper.GetInt64("racConfig.clientId"),
			cpassword:     viper.GetString("racConfig.cpassword"),
		}
		return racCfg
	}

	if cfg == nil {
		racCfg = &racConfig{
			hbDuration:    10 * time.Second,
			trustDuration: 120 * time.Second,
			clientId:      -1,
			cpassword:     "",
		}
	}

	return racCfg
}

// Save saves all config variables to the config.yaml file.
func Save() {
	if cfg != nil {
		viper.Set("database.host", cfg.host)
		viper.Set("database.dbname", cfg.dbName)
		viper.Set("database.user", cfg.user)
		viper.Set("database.password", cfg.password)
		viper.Set("database.port", cfg.port)
		viper.Set("racConfig.hbDuration", cfg.hbDuration)
		viper.Set("racConfig.trustDuration", cfg.trustDuration)
		viper.Set("racConfig.clientId", cfg.clientId)
		viper.Set("racConfig.cpassword", cfg.password)
		viper.Set("rasConfig.mgrStrategy", cfg.mgrStrategy)
		viper.Set("rasConfig.changeTime", cfg.changeTime)
		err := viper.WriteConfig()
		if err != nil {
			_ = viper.SafeWriteConfig()
		}
	}
}

// Save saves RacConfig variables to the config.yaml file.
func SaveClient() {
	if racCfg != nil {
		viper.Set("racConfig.hbDuration", racCfg.hbDuration)
		viper.Set("racConfig.trustDuration", racCfg.trustDuration)
		viper.Set("racConfig.clientId", racCfg.clientId)
		viper.Set("racConfig.cpassword", racCfg.cpassword)
		err := viper.WriteConfig()
		if err != nil {
			_ = viper.SafeWriteConfig()
		}
	}
}

func (c *config) GetHost() string {
	return c.host
}

func (c *config) SetHost(host string) {
	c.host = host
}

func (c *config) GetDBName() string {
	return c.dbName
}

func (c *config) SetDBName(dbName string) {
	c.dbName = dbName
}

func (c *config) GetUser() string {
	return c.user
}

func (c *config) SetUser(user string) {
	c.user = user
}

func (c *config) GetPassword() string {
	return c.password
}

func (c *config) SetPassword(password string) {
	c.password = password
}

func (c *config) GetPort() int {
	return c.port
}

func (c *config) SetPort(port int) {
	c.port = port
}

func (c *config) GetTrustDuration() time.Duration {
	return c.trustDuration
}

func (c *config) SetTrustDuration(d time.Duration) {
	c.trustDuration = d
}

func (c *racConfig) GetHBDuration() time.Duration {
	return c.hbDuration
}

func (c *racConfig) SetHBDuration(d time.Duration) {
	c.hbDuration = d
}

func (c *racConfig) GetClientId() int64 {
	return c.clientId
}

func (c *racConfig) SetClientId(id int64) {
	c.clientId = id
}

func (c *config) GetMgrStrategy() string {
	return c.mgrStrategy
}

func (c *config) SetMgrStrategy(s string) {
	c.mgrStrategy = s
	c.changeTime = time.Now()
}

func (c *config) GetChangeTime() time.Time {
	return c.changeTime
}

func (c *config) SetExtractRules(e entity.ExtractRules) {
	c.rasConfig.extractRules = e
}

func (c *config) GetExtractRules() entity.ExtractRules {
	return c.rasConfig.extractRules
}
