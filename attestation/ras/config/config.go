/*
Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
	"errors"
	"fmt"
	"github.com/spf13/viper"
	"time"
)

var defaultConfigPath = []string{
	"./",
}

type Config struct {
	path string
	rasConfig RASConfig
	racConfig RACConfig
}
type (
	RASConfig struct {
		mgrStrategy string
		changeTime  time.Time
	}

	RACConfig struct {
		hbDuration    time.Duration // heartbeat duration
		trustDuration time.Duration // trust state duration
	}
)

var config *Config

/*
	CreateConfig creates Config object if it was not initialized.
	The path can't be empty when CreateConfig is called first time. Normally it is called when app initializes.
	The path can't be modified when app running.
	If the path is empty, CreateConfig return current Config object. So after called for the first time,
	the parameter is always "".
*/
func CreateConfig(path string) (*Config, error) {
	if config != nil && path == "" {
		return config, nil
	}
	if config != nil && path != "" {
		return config, errors.New("the parameter must be empty because config has been initialized")
	}
	if config == nil && path == "" {
		return config, errors.New("the parameter can't be empty for initializing config")
	}
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(path)
	err := viper.ReadInConfig()
	if err != nil {
		fmt.Println("failed to read config file")
		return nil, err
	}
	hbDuration := viper.GetDuration("racConfig.hbDuration")
	trustDuration := viper.GetDuration("racConfig.trustDuration")
	mgrStrategy := viper.GetString("rasConfig.mgrStrategy")
	changeTime := viper.GetTime("rasConfig.changeTime")
	c := &Config{
		path: path,
		rasConfig: RASConfig{
			mgrStrategy: mgrStrategy,
			changeTime:  changeTime,
		},
		racConfig: RACConfig{
			hbDuration:    hbDuration,
			trustDuration: trustDuration,
		},
	}
	return c, nil
}

// GetDefault returns the global default config object.
func GetDefault() *Config {
	var config *Config
	for _, p := range defaultConfigPath {
		config, _ = CreateConfig(p)
	}
	if config == nil {
		config = &Config{
			rasConfig: RASConfig{
				mgrStrategy: "auto",
				changeTime:  time.Now(),
			},
			racConfig: RACConfig{
				hbDuration:    10 * time.Second,
				trustDuration: 120 * time.Second,
			},
		}
	}
	return config
}

func (c *Config) GetHBDuration() time.Duration {
	return c.racConfig.hbDuration
}

/*
	SetHBDuration just set hbDuration for now, it can't change the config file.
	If you want to change the config file, please use ChangeConfig.
*/
func (c *Config) SetHBDuration(d time.Duration) {
	c.racConfig.hbDuration = d
}

/*
	ChangeConfig just change the config file, it can't set config value for now.
	If you want to set current config value, please use SetXXX function.
*/
func (c *Config) ChangeConfig(hbDuration time.Duration, trustDuration time.Duration, mgrStrategy string) error {
	viper.Set("racConfig.hbDuration", hbDuration)
	viper.Set("racConfig.trustDuration", trustDuration)
	viper.Set("rasConfig.mgrStrategy", mgrStrategy)
	viper.Set("rasConfig.changeTime", time.Now())
	err := viper.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) GetTrustDuration() time.Duration {
	return c.racConfig.trustDuration
}

func (c *Config) SetTrustDuration(d time.Duration) {
	c.racConfig.trustDuration = d
}

func (c *Config) GetMgrStrategy() string {
	return c.rasConfig.mgrStrategy
}

func (c *Config) SetMgrStrategy(s string) {
	c.rasConfig.mgrStrategy = s
	c.rasConfig.changeTime = time.Now()
}

func (c *Config) GetChangeTime() time.Time {
	return c.rasConfig.changeTime
}

func (c *Config) SetChangeTime(n time.Time) {
	c.rasConfig.changeTime = n
}
