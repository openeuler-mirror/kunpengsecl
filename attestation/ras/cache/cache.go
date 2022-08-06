/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-09-17
Description: Moniter RAC status and check its trust report state.
	1. 2022-01-17	wucaijun
		change to a simple cache algorithem, add none and ikCert.
	2. 2022-01-29	wucaijun
		add bases in the cache to enhance performance.
*/

// cache package saves information of client status to enhance performance.
package cache

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
)

const (
	defaultBaseRows = 10
	StrUnknown      = "unknown"
	StrTrusted      = "trusted"
	StrUntrusted    = "untrusted"
)

type (
	// Cache stores the latest status of one RAC client and commands.
	Cache struct {
		regtime      string
		online       bool
		hostTrusted  string
		isAutoUpdate bool //true表示信任下一次的可信报告，不验证直接抽取更新基准值；false则正常对下一次报告进行验证
		// current commands for RAC.
		commands uint64
		// heartbeat expiration, used for judging whether RAC heartbeat is expired.
		hbExpiration time.Time
		// trust report expiration, used for maintain report freshness.
		trustExpiration  time.Time
		onlineExpiration time.Time
		// for remote attestation
		nonce  uint64
		ikCert *x509.Certificate
		// for verify process
		Bases []*typdefs.BaseRow
	}
)

// NewCache creates a new cache to save client information.
func NewCache() *Cache {
	c := &Cache{
		regtime:         "",
		online:          false,
		hostTrusted:     StrUnknown,
		isAutoUpdate:    false,
		commands:        typdefs.CmdNone,
		trustExpiration: time.Now(),
		nonce:           0,
		ikCert:          nil,
		Bases:           make([]*typdefs.BaseRow, 0, defaultBaseRows),
	}
	return c
}

// UpdateHeartBeat is called when receives heart beat message from RAC.
func (c *Cache) UpdateHeartBeat(hb time.Duration) {
	// Once get a heart beat message then extends the expiration.
	c.online = true
	c.hbExpiration = time.Now().Add(hb)
	c.GetTrusted()
}

// UpdateTrustReport is called when receives trust report message from RAC.
func (c *Cache) UpdateTrustReport(trust time.Duration) {
	c.trustExpiration = time.Now().Add(trust)
}

func (c *Cache) UpdateOnline(t time.Duration) {
	c.onlineExpiration = time.Now().Add(t)
}

// IsHeartBeatExpired checks if the client is expired.
func (c *Cache) IsHeartBeatExpired() bool {
	return time.Now().After(c.hbExpiration)
}

// HasCommands checks if the client has some commands.
func (c *Cache) HasCommands() bool {
	return c.commands != typdefs.CmdNone
}

// ClearCommands clears the client commands.
func (c *Cache) ClearCommands() {
	c.commands = typdefs.CmdNone
}

// SetCommands saves the new commands for waiting.
func (c *Cache) SetCommands(cmds uint64) {
	c.commands |= cmds
}

// GetCommands gets the pending commands of client.
func (c *Cache) GetCommands() uint64 {
	return c.commands
}

// SetVerified sets the trusted field.
func (c *Cache) SetTrusted(v string) {
	c.hostTrusted = v
}

// GetTrusted checks where the RAC trust report is valid or not.
func (c *Cache) GetTrusted() string {
	// After trust report expiration there is no one report received,
	// the RAC can't be trusted any more and needs to get a new trust report.
	if !c.online {
		c.hostTrusted = StrUnknown
	}
	if time.Now().After(c.trustExpiration) {
		c.SetCommands(typdefs.CmdGetReport)
		c.hostTrusted = StrUnknown
	}
	return c.hostTrusted
}

// GetNonce returns a nonce value for remote attestation trust report.
func (c *Cache) GetNonce() uint64 {
	var a [8]byte
	_, err := rand.Read(a[:])
	if err != nil {
		return 0
	}
	c.nonce = binary.LittleEndian.Uint64(a[:])
	return c.nonce
}

// CompareNonce checks the returned nonce match or not.
func (c *Cache) CompareNonce(n uint64) bool {
	return c.nonce == n
}

// GetIKeyCert returns the client IK certificate for validate the trust report.
func (c *Cache) GetIKeyCert() *x509.Certificate {
	return c.ikCert
}

// SetIKeyCert saves the client IK certificate in cache to enhance performance.
func (c *Cache) SetIKeyCert(pemCert string) {
	c.ikCert, _, _ = cryptotools.DecodeKeyCertFromPEM([]byte(pemCert))
}

// GetRegTime returns the client register time.
func (c *Cache) GetRegTime() string {
	return c.regtime
}

// SetRegTime saves the client register time.
func (c *Cache) SetRegTime(v string) {
	c.regtime = v
}

func (c *Cache) GetOnline() bool {
	if time.Now().After(c.onlineExpiration) {
		c.online = false
	} else {
		c.online = true
	}
	return c.online
}

// GetIsAutoUpdate returns the client autoupdate strategy.
func (c *Cache) GetIsAutoUpdate() bool {
	return c.isAutoUpdate
}

// SetIsAutoUpdate saves the client autoppdate strategy.
func (c *Cache) SetIsAutoUpdate(v bool) {
	c.isAutoUpdate = v
}

func (c *Cache) GetTrustExpiration() time.Time {
	return c.trustExpiration
}
