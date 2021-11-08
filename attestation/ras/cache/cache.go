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
Description: Moniter RAC status and check its trust report state.
*/

package cache

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

/*
 In the heartbeat reply message, it will send some commands to RAC.
*/
const (
	cmdSENDCONF  uint64 = 1 << iota // send new configuration to RAC.
	cmdGETREPORT                    // get a new trust report from RAC.
	cmdNONE      uint64 = 0         // clear all pending commands.
)

type (
	// Cache stores the latest status of one RAC target.
	Cache struct {
		command         uint64
		hbExpiration    time.Time
		trustExpiration time.Time
	}
)

// UpdateHeartBeat is called when receives heart beat message from RAC.
func (c *Cache) UpdateHeartBeat() {
	cfg := config.GetDefault()
	// Once get a heart beat message then extends the expiration.
	c.hbExpiration = time.Now().Add(cfg.GetHBDuration())
	// If half past of trust report expiration, we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-cfg.GetTrustDuration() / 2)) {
		c.GetTrustReport()
	}
}

// UpdateTrustReport is called when receives trust report message from RAC.
func (c *Cache) UpdateTrustReport() {
	cfg := config.GetDefault()
	c.trustExpiration = time.Now().Add(cfg.GetTrustDuration())
}

func (c *Cache) IsHeartBeatExpired() bool {
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

func (c *Cache) GetCommands() uint64 {
	return c.command
}

// IsReportValid checks where the RAC trust report is valid or not.
func (c *Cache) IsReportValid() bool {
	cfg := config.GetDefault()
	// After trust report expiration there is no one report received,
	// the RAC can't be trusted any more and needs to get a new trust report.
	if time.Now().After(c.trustExpiration) {
		c.GetTrustReport()
		return false
	}
	// Even half past of trust report expiration we still trust the report
	// of this RAC, but we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-cfg.GetTrustDuration() / 2)) {
		c.GetTrustReport()
	}
	return true
}

func (c *Cache) CreateNonce() (uint64, error) {
	var a [8]byte
	_, err := rand.Read(a[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(a[:]), nil
}
