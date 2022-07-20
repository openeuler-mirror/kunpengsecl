/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
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
*/

package cache

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
)

/*
 In the heartbeat reply message, it will send some commands to RAC.
*/
const (
	// const start with CMD is used for nextAction which determind what to do for RAC.
	CMDSENDCONF  uint64 = 1 << iota // send new configuration to RAC.
	CMDGETREPORT                    // get a new trust report from RAC.
	CMDNONE      uint64 = 0         // clear all pending commands.
	// const start with STS is used for trust status.
	STSUNKNOWN   = "unknown"
	STSTRUSTED   = "trusted"
	STSUNTRUSTED = "untrusted"
	// default RAC number in the cache.
	DEFAULTRACNUM int = 1000
	// ima string
	IMASTR = "ima"
)

type (
	// Cache stores the latest status of one RAC target.
	Cache struct {
		cm *CacheMgr
		// one cache corresponds to one client id.
		cid int64
		// current command for RAC.
		command uint64
		// heartbeat expiration, used for judging whether RAC heartbeat is expired.
		hbExpiration time.Time
		// trust report expiration,used for maintain report freshness.
		trustExpiration time.Time
	}

	// manager of the caches for all registered RACs.
	CacheMgr struct {
		// sync lock.
		sync.Mutex
		// all current RAC and its corresponding cache map.
		caches map[int64]*Cache
		// for verifying report if it is trusted.
		vm *verifier.VerifierMgr
	}
)

// CreateCacheMgr creates a new CacheMgr with given initCap as the initial capacity of the supported RAC number
func CreateCacheMgr(initCap int, vm *verifier.VerifierMgr) *CacheMgr {
	return &CacheMgr{
		caches: make(map[int64]*Cache, initCap),
		vm:     vm,
	}
}

// Initialize fills CacheMgr with all caches of clients synced with trustmgr
func (cm *CacheMgr) Initialize() error {
	ids, err := trustmgr.GetAllRegisteredClientID()
	if err != nil {
		return err
	}

	for _, id := range ids {
		cm.caches[id] = &Cache{
			cm:      cm,
			cid:     id,
			command: CMDNONE,
		}
		cm.caches[id].UpdateHeartBeat()
		cm.caches[id].UpdateTrustReport()
	}

	return nil
}

// GetCache returns the cache for client with the given cid
func (cm *CacheMgr) GetCache(cid int64) *Cache {
	return cm.caches[cid]
}

// CreateCache create a cache for given client and returns the cache
func (cm *CacheMgr) CreateCache(cid int64) *Cache {
	if cm.caches[cid] != nil {
		return nil
	}

	cm.caches[cid] = &Cache{
		cm:      cm,
		cid:     cid,
		command: CMDNONE,
	}
	cm.caches[cid].UpdateHeartBeat()
	cm.caches[cid].UpdateTrustReport()
	return cm.caches[cid]
}

// RemoveCache delete cache for client with the given cid
func (cm *CacheMgr) RemoveCache(cid int64) {
	delete(cm.caches, cid)
}

// GetAllClientID returns the slice of all availabe client id
func (cm *CacheMgr) GetAllClientID() []int64 {
	ids := make([]int64, 0, len(cm.caches))
	for key := range cm.caches {
		ids = append(ids, key)
	}
	return ids
}

// GetAllTrustStatus returns the trust status of all the clients
func (cm *CacheMgr) GetAllTrustStatus() map[int64]string {
	m := make(map[int64]string, len(cm.caches))
	for k, c := range cm.caches {
		m[k] = c.GetTrustStatus()
	}
	return m
}

func (cm *CacheMgr) GetTrustStatusById(clientId int64) string {
	if ca, ok := cm.caches[clientId]; ok {
		return ca.GetTrustStatus()
	}
	return STSUNKNOWN
}

func (cm *CacheMgr) GetAllContainerTrustStatus() (map[string]string, error) {
	cons, err := trustmgr.GetAllContainerUUIds()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, conId := range cons {
		con, err := trustmgr.GetContainerByUUId(conId)
		if err != nil {
			return nil, err
		}
		if cache, ok := cm.caches[con.ClientId]; ok {
			m[conId] = cache.GetContainerTrustStatus(conId)
		}
	}
	return m, nil
}

func (cm *CacheMgr) GetDeviceTrustStatusById(deviceId int64) string {
	dev, err := trustmgr.GetDeviceById(deviceId)
	if err != nil {
		return STSUNKNOWN
	}
	if cache, ok := cm.caches[dev.ClientId]; ok {
		return cache.GetDeviceTrustStatus(deviceId)
	}
	return STSUNKNOWN
}

func (cm *CacheMgr) GetAllDeviceTrustStatus() (map[int64]string, error) {
	devs, err := trustmgr.GetAllDeviceIds()
	if err != nil {
		return nil, err
	}
	m := map[int64]string{}
	for _, devId := range devs {
		dev, err := trustmgr.GetDeviceById(devId)
		if err != nil {
			return nil, err
		}
		if cache, ok := cm.caches[dev.ClientId]; ok {
			m[devId] = cache.GetDeviceTrustStatus(devId)
		}
	}
	return m, nil
}

func (cm *CacheMgr) GetContainerTrustStatusByUUId(uuID string) string {
	con, err := trustmgr.GetContainerByUUId(uuID)
	if err != nil {
		return STSUNKNOWN
	}
	if cache, ok := cm.caches[con.ClientId]; ok {
		return cache.GetContainerTrustStatus(uuID)
	}
	return STSUNKNOWN
}

func (cm *CacheMgr) SyncConfig() {
	for _, c := range cm.caches {
		c.SetCMDSendConfigure()
	}
}

// GetTrustStatus returns the trust status of the corresponding client
func (c *Cache) GetTrustStatus() string {
	report, err := trustmgr.GetLatestReportById(c.cid)
	if err != nil {
		return STSUNKNOWN
	}
	if c.isHeartBeatLost() || c.isReportExpired(report.ReportTime) {
		return STSUNKNOWN
	}
	bv, err := trustmgr.GetBaseValueById(c.cid)
	if err != nil {
		return STSUNKNOWN
	}
	if err = c.cm.vm.Verify(bv, report); err == nil {
		return STSTRUSTED
	}

	return STSUNTRUSTED
}

func (c *Cache) GetContainerTrustStatus(uuid string) string {
	cid := c.cid
	bv, err := trustmgr.GetBaseValueById(cid)
	if err != nil {
		return STSUNKNOWN
	}
	report, err := trustmgr.GetLatestReportById(cid)
	if err != nil {
		return STSUNKNOWN
	}
	if c.isHeartBeatLost() || c.isReportExpired(report.ReportTime) {
		return STSUNKNOWN
	}
	if err = c.cm.vm.Verify(bv, report); err != nil {
		return STSUNTRUSTED
	}
	cbv, err := trustmgr.GetContainerBaseValueByUUId(uuid)
	if err != nil {
		return STSUNKNOWN
	}
	m := []entity.Measurement{}
	for k, v := range cbv.Value {
		m = append(m, entity.Measurement{
			Type:  IMASTR,
			Name:  k,
			Value: v,
		})
	}
	compareCbv := entity.MeasurementInfo{
		ClientID: cid,
		Manifest: m,
	}
	if err = c.cm.vm.Verify(&compareCbv, report); err != nil {
		return STSUNTRUSTED
	}
	return STSTRUSTED
}

func (c *Cache) GetDeviceTrustStatus(deviceId int64) string {
	dev, err := trustmgr.GetDeviceById(deviceId)
	if err != nil {
		return STSUNKNOWN
	}
	cid := dev.ClientId
	bv, err := trustmgr.GetBaseValueById(cid)
	if err != nil {
		return STSUNKNOWN
	}
	report, err := trustmgr.GetLatestReportById(cid)
	if err != nil {
		return STSUNKNOWN
	}
	if c.isHeartBeatLost() || c.isReportExpired(report.ReportTime) {
		return STSUNKNOWN
	}
	if err = c.cm.vm.Verify(bv, report); err != nil {
		return STSUNTRUSTED
	}
	dbv, err := trustmgr.GetDeviceBaseValueById(deviceId)
	if err != nil {
		return STSUNKNOWN
	}
	m := []entity.Measurement{}
	for k, v := range dbv.Value {
		m = append(m, entity.Measurement{
			Type:  IMASTR,
			Name:  k,
			Value: v,
		})
	}
	compareCbv := entity.MeasurementInfo{
		ClientID: cid,
		Manifest: m,
	}
	if err = c.cm.vm.Verify(&compareCbv, report); err != nil {
		return STSUNTRUSTED
	}
	return STSTRUSTED
}

func (c *Cache) isHeartBeatLost() bool {
	cfg := config.GetDefault(config.ConfServer)
	// Once we missed 3 hb, then report hb lost.
	if time.Now().After(c.hbExpiration.Add(cfg.GetHBDuration() * 2)) {
		return true
	}

	return false
}

func (c *Cache) isReportExpired(reportTime time.Time) bool {
	cfg := config.GetDefault(config.ConfServer)
	// Once we pass the trust duration, report report expired.
	if time.Now().After(reportTime.Add(cfg.GetTrustDuration())) {
		return true
	}

	return false
}

// UpdateHeartBeat is called when receives heart beat message from RAC.
func (c *Cache) UpdateHeartBeat() {
	cfg := config.GetDefault(config.ConfServer)
	// Once get a heart beat message then extends the expiration.
	c.hbExpiration = time.Now().Add(cfg.GetHBDuration())
	// If half past of trust report expiration, we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-cfg.GetTrustDuration() / 2)) {
		c.SetCMDGetTrustReport()
	}
}

// UpdateTrustReport is called when receives trust report message from RAC.
func (c *Cache) UpdateTrustReport() {
	cfg := config.GetDefault(config.ConfServer)
	c.trustExpiration = time.Now().Add(cfg.GetTrustDuration())
}

func (c *Cache) IsHeartBeatExpired() bool {
	return time.Now().After(c.hbExpiration)
}

func (c *Cache) HasCommands() bool {
	return c.command != CMDNONE
}

func (c *Cache) ClearCommands() {
	c.command = CMDNONE
}

func (c *Cache) SetCMDSendConfigure() {
	c.command |= CMDSENDCONF
}

func (c *Cache) SetCMDGetTrustReport() {
	c.command |= CMDGETREPORT
}

func (c *Cache) GetCommands() uint64 {
	return c.command
}

// IsReportValid checks where the RAC trust report is valid or not.
func (c *Cache) IsReportValid() bool {
	cfg := config.GetDefault(config.ConfServer)
	// After trust report expiration there is no one report received,
	// the RAC can't be trusted any more and needs to get a new trust report.
	if time.Now().After(c.trustExpiration) {
		c.SetCMDGetTrustReport()
		return false
	}
	// Even half past of trust report expiration we still trust the report
	// of this RAC, but we need to get a new trust report.
	if time.Now().After(c.trustExpiration.Add(-cfg.GetTrustDuration() / 2)) {
		c.SetCMDGetTrustReport()
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
