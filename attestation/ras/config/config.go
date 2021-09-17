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
	"time"
)

type (
	RASConfig struct {
		// TODO:
	}

	RACConfig struct {
		hbDuration    time.Duration // heartbeat duration
		trustDuration time.Duration // trust state duration
	}
)

func (c *RACConfig) GetHBDuration() time.Duration {
	return c.hbDuration
}

func (c *RACConfig) SetHBDuration(d time.Duration) {
	c.hbDuration = d
}

func (c *RACConfig) GetTrustDuration() time.Duration {
	return c.trustDuration
}

func (c *RACConfig) SetTrustDuration(d time.Duration) {
	c.trustDuration = d
}
