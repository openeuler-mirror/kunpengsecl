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
Description: Moniter RAC status and judge its trust state.
*/

package cache

import (
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

/*
 In the heartbeat reply message, it will send some commands to RAC.
*/
const (
	cmdSENDCONF  int = 1 << iota // send new configuration to RAC.
	cmdGETREPORT                 // get a new trust report from RAC.
	cmdNONE      int = 0         // clear all pending commands.
)

type (
	// Cache stores the latest status of one RAC target.
	Cache struct {
		command         int
		hbExpiration    time.Time
		trustExpiration time.Time
		config.RACConfig
	}
)

// Update is called when receives heart beat message from RAC.
func (c *Cache) Update() {
	// Half past of trust expiration, we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-c.GetTrustDuration() / 2)) {
		c.GetTrustReport()
	}
	// Once get a new heart beat message then extends the heart beat expiration.
	c.hbExpiration = time.Now().Add(time.Second * c.GetHBDuration())
}

func (c *Cache) IsExpire() bool {
	return time.Now().After(c.hbExpiration)
}

func (c *Cache) HasCommands() bool {
	return c.command != cmdNONE
}

func (c *Cache) ClearCommands() {
	c.command = cmdNONE
}

func (c *Cache) SendConfigure() {
	c.command |= cmdSENDCONF
}

func (c *Cache) GetTrustReport() {
	c.command |= cmdGETREPORT
}

func (c *Cache) IsTrust() bool {
	// After trust expiration there is no new trust report, the RAC can't
	// be trusted and needs to get a new trust report.
	if time.Now().After(c.trustExpiration) {
		c.GetTrustReport()
		return false
	}
	// Even half past of trust expiration we still trust this RAC,
	// but we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-c.GetTrustDuration() / 2)) {
		c.GetTrustReport()
	}
	return true
}
