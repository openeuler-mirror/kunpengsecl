/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3
Create: 2021-09-17
Description: manage the client trust status.
	1. 2022-01-17	wucaijun
		use cache/database/files three levels arch to implement a simple
		but high performance client trust management algorithm.
	2. 2022-01-28	wucaijun
		modify the mutex lock scope to enhance performance.
	3. 2022-01-30	wucaijun
		add the storeDb for using limited file handle to enhance database performance.
*/

// trustmgr package manages all clients information, validates trust report,
// saves reports, verifies reports according to customer's specific definitions,
// and supports rest api to show all information.
package trustmgr

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"

	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"github.com/google/go-tpm/tpm2"
	_ "github.com/lib/pq"
)

const (
	constRacDefault = 5000

	// for database management sql
	sqlRegisterClientByIK                = `INSERT INTO client(regtime, registered, info, ikcert) VALUES ($1, $2, $3, $4) RETURNING id`
	sqlFindAllClients                    = `SELECT id, regtime FROM client WHERE 1=1`
	sqlFindAllEnabledClients             = `SELECT id, regtime, ikcert FROM client WHERE registered=true`
	sqlFindClientByID                    = `SELECT regtime, registered, info, ikcert FROM client WHERE id=$1`
	sqlFindClientIDByIK                  = `SELECT id FROM client WHERE ikcert=$1`
	sqlFindClientFullByIK                = `SELECT id, regtime, registered, info FROM client WHERE ikcert=$1`
	sqlFindClientsByInfo                 = `SELECT id, regtime, registered, info, ikcert FROM client WHERE info @> $1`
	sqlFindReportsByClientID             = `SELECT id, clientid, createtime, validated, trusted FROM report WHERE clientid=$1 ORDER BY createtime ASC`
	sqlFindReportByID                    = `SELECT id, clientid, createtime, validated, trusted, quoted, signature, pcrlog, bioslog, imalog FROM report WHERE id=$1`
	sqlFindBaseValuesByClientID          = `SELECT id, basetype, uuid, createtime, name, enabled FROM base WHERE clientid=$1 ORDER BY createtime ASC`
	sqlFindHostBaseValuesByClientID      = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE clientid=$1 AND basetype="host" ORDER BY createtime ASC`
	sqlFindContainerBaseValuesByClientID = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE clientid=$1 AND basetype="container" ORDER BY createtime ASC`
	sqlFindDeviceBaseValuesByClientID    = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE clientid=$1 AND basetype="device" ORDER BY createtime ASC`
	sqlFindBaseValueByID                 = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE id=$1 ORDER BY createtime ASC`
	sqlFindBaseValueByUuid               = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE uuid=$1`
	sqlDeleteReportByID                  = `DELETE FROM report WHERE id=$1`
	sqlDeleteBaseValueByID               = `DELETE FROM base WHERE id=$1`
	sqlDeleteClientByID                  = `DELETE FROM client WHERE id=$1`
	sqlRegisterClientByID                = `UPDATE client SET registered=true WHERE id=$1`
	sqlUnRegisterClientByID              = `UPDATE client SET registered=false WHERE id=$1`
	sqlUpdateClientByID                  = `UPDATE client SET info=$2 WHERE id=$1`
	sqlInsertTrustReport                 = `INSERT INTO report(clientid, createtime, validated, trusted, quoted, signature, pcrlog, bioslog, imalog) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	sqlInsertBase                        = `INSERT INTO base(clientid, basetype, uuid, createtime, enabled, name, pcr, bios, ima) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	sqlModifyBaseValuesByClientID        = `UPDATE base set enabled=false WHERE clientid=$1 AND basetype="host"`
	sqlModifyBaseValueByid               = `UPDATE base set enabled=false WHERE id=$1`
)

type (
	// TrustManager handles all clients information.
	TrustManager struct {
		// control the cache accessing
		mu sync.Mutex
		// all clients status cache. (level one)
		cache map[int64]*cache.Cache
		// save clients status information, backup of cache and support
		// rest api search operations... (level two)
		db *sql.DB
	}
)

var (
	tmgr *TrustManager = nil
)

// CreateTrustManager creates a new trust manager with a global cache
// and a database connection poll to enhance performance.
func CreateTrustManager(dbType, dbConfig string) {
	var err error
	var id int64
	var ik string
	var regtime time.Time
	if tmgr != nil {
		return
	}
	tmgr = &TrustManager{}
	tmgr.db, err = sql.Open(dbType, dbConfig)
	if err != nil {
		return
	}
	tmgr.mu.Lock()
	tmgr.cache = make(map[int64]*cache.Cache, constRacDefault)
	tmgr.mu.Unlock()
	// read clients info from database into cache.
	rows, err := tmgr.db.Query(sqlFindAllEnabledClients)
	if err != nil {
		tmgr.db.Close()
		tmgr.mu.Lock()
		tmgr.cache = nil
		tmgr.mu.Unlock()
		tmgr = nil
		return
	}
	for rows.Next() {
		err = rows.Scan(&id, &regtime, &ik)
		if err == nil {
			c := cache.NewCache()
			c.SetRegTime(regtime.Format(typdefs.StrTimeFormat))
			c.SetIKeyCert(ik)
			hb, err := FindHostBaseValuesByClientID(id)
			if err == nil {
				c.HostBases = hb
			}
			cb, err := FindContainerBaseValuesByClientID(id)
			if err == nil {
				c.ContainerBases = cb
			}
			db, err := FindDeviceBaseValuesByClientID(id)
			if err == nil {
				c.DeviceBases = db
			}
			tmgr.cache[id] = c
		}
	}
	createStorePipe(dbType, dbConfig)
}

// ReleaseTrustManager releases the manager database connection.
func ReleaseTrustManager() {
	if tmgr == nil {
		return
	}
	if tmgr.db != nil {
		tmgr.db.Close()
		tmgr.db = nil
	}
	tmgr.mu.Lock()
	tmgr.cache = nil
	tmgr.mu.Unlock()
	tmgr = nil
	releaseStorePipe()
}

// ModifyEnabledByClientID modify all hostbase enabled=false
func ModifyEnabledByClientID(id int64) error {
	if tmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := tmgr.db.Query(sqlModifyBaseValuesByClientID, id)
	if err != nil {
		return err
	}
	return nil
}

// ModifyEnabledByID modify base enabled=false
func ModifyEnabledByID(id int64) error {
	if tmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := tmgr.db.Query(sqlModifyBaseValueByid, id)
	if err != nil {
		return err
	}
	return nil
}

// GetCache returns the client cache ref by id or nil if not find.
func GetCache(id int64) (*cache.Cache, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	tmgr.mu.Lock()
	defer tmgr.mu.Unlock()
	c, ok := tmgr.cache[id]
	if ok {
		return c, nil
	}
	return nil, typdefs.ErrDoesnotRegistered
}

// GetAllNodes returns all clients cache information from "f" to "t"
// and returns a list nodes to rest api.
func GetAllNodes(f, t int64) (map[int64]*typdefs.NodeInfo, error) {
	nodes := make(map[int64]*typdefs.NodeInfo, constRacDefault)
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	tmgr.mu.Lock()
	defer tmgr.mu.Unlock()
	var id int64
	var regitime string
	rows, err := tmgr.db.Query(sqlFindAllClients)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		err = rows.Scan(&id, &regitime)
		if err == nil {
			n := typdefs.NodeInfo{
				ID:           id,
				RegTime:      regitime,
				Registered:   false,
				Online:       false,
				Trusted:      cache.StrUnknown,
				IsAutoUpdate: false,
			}
			nodes[id] = &n
		}
	}
	for i, v := range tmgr.cache {
		if f <= i && i < t {
			nodes[i].Registered = true
			nodes[i].Online = v.GetOnline()
			nodes[i].Trusted = v.GetTrusted()
			nodes[i].IsAutoUpdate = v.GetIsAutoUpdate()
		}
	}
	return nodes, nil
}

// UpdateAllNodes lets all clients to update configuration from ras in next heart beat.
func UpdateAllNodes() {
	if tmgr == nil {
		return
	}
	tmgr.mu.Lock()
	defer tmgr.mu.Unlock()
	for _, n := range tmgr.cache {
		n.SetCommands(typdefs.CmdSendConfig)
	}
}

// UpdateeCaches sets all clients's isAutoUpdate to true.
func UpdateCaches() {
	if tmgr == nil {
		return
	}
	tmgr.mu.Lock()
	defer tmgr.mu.Unlock()
	for _, n := range tmgr.cache {
		n.SetIsAutoUpdate(true)
	}
}

// RegisterClientByIK registers a new client by ikCert and info. if there is a existing ik, register will fail.
func RegisterClientByIK(ikCert, info string, registered bool) (*typdefs.ClientRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	c := typdefs.ClientRow{IKCert: ikCert}
	err := tmgr.db.QueryRow(sqlFindClientIDByIK, ikCert).Scan(&c.ID)
	if err == nil {
		return nil, typdefs.ErrAlreadyRegistered
	}
	c = typdefs.ClientRow{
		RegTime:    time.Now(),
		Registered: registered,
		Info:       info,
		IKCert:     ikCert,
	}
	err = tmgr.db.QueryRow(sqlRegisterClientByIK, c.RegTime,
		c.Registered, c.Info, c.IKCert).Scan(&c.ID)
	if err != nil {
		return nil, err
	}
	if registered {
		ca := cache.NewCache()
		ca.SetRegTime(c.RegTime.Format(typdefs.StrTimeFormat))
		ca.SetIKeyCert(ikCert)
		tmgr.mu.Lock()
		tmgr.cache[c.ID] = ca
		tmgr.mu.Unlock()
	}
	return &c, nil
}

func RegisterClientByID(id int64, regtime time.Time, ik string) {
	if tmgr == nil {
		return
	}
	tmgr.mu.Lock()
	c := cache.NewCache()
	c.SetRegTime(regtime.Format(typdefs.StrTimeFormat))
	c.SetIKeyCert(ik)
	tmgr.cache[id] = c
	tmgr.mu.Unlock()
	tmgr.db.Exec(sqlRegisterClientByID, id)
}

func UnRegisterClientByID(id int64) {
	_, err := GetCache(id)
	if err != nil {
		return
	}
	tmgr.mu.Lock()
	delete(tmgr.cache, id)
	tmgr.mu.Unlock()
	tmgr.db.Exec(sqlUnRegisterClientByID, id)
}

// FindClientByIK gets client from database by ak.
func FindClientByIK(ikCert string) (*typdefs.ClientRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	c := typdefs.ClientRow{IKCert: ikCert}
	err := tmgr.db.QueryRow(sqlFindClientFullByIK, ikCert).Scan(&c.ID,
		&c.RegTime, &c.Registered, &c.Info)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindClientByID gets client from database by id.
func FindClientByID(id int64) (*typdefs.ClientRow, error) {
	c := typdefs.ClientRow{ID: id}
	err := tmgr.db.QueryRow(sqlFindClientByID, id).Scan(&c.RegTime,
		&c.Registered, &c.Info, &c.IKCert)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindClientsByInfo gets clients from database ref by info,
// info must be a json string like `{"key": "value"}`.
func FindClientsByInfo(info string) ([]typdefs.ClientRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindClientsByInfo, info)
	if err != nil {
		return nil, err
	}
	cs := make([]typdefs.ClientRow, 0, 10)
	for rows.Next() {
		c := typdefs.ClientRow{}
		err2 := rows.Scan(&c.ID, &c.RegTime, &c.Registered, &c.Info, &c.IKCert)
		if err2 != nil {
			return nil, err2
		}
		cs = append(cs, c)
	}
	return cs, nil
}

func DeleteClientByID(id int64) error {
	if tmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := tmgr.db.Exec(sqlDeleteClientByID, id)
	if err != nil {
		return err
	}
	return nil
}

// FindReportsByClientID returns all reports by a specific client id.
func FindReportsByClientID(id int64) ([]typdefs.ReportRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindReportsByClientID, id)
	if err != nil {
		return nil, err
	}
	reports := make([]typdefs.ReportRow, 0, 100)
	for rows.Next() {
		res := typdefs.ReportRow{}
		err2 := rows.Scan(&res.ID, &res.ClientID,
			&res.CreateTime, &res.Validated, &res.Trusted)
		if err2 != nil {
			return nil, err2
		}
		reports = append(reports, res)
	}
	return reports, nil
}

// FindReportByID returns the report by a specific report id.
func FindReportByID(id int64) (*typdefs.ReportRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	report := typdefs.ReportRow{}
	err := tmgr.db.QueryRow(sqlFindReportByID, id).Scan(&report.ID, &report.ClientID,
		&report.CreateTime, &report.Validated, &report.Trusted, &report.Quoted,
		&report.Signature, &report.PcrLog, &report.BiosLog, &report.ImaLog)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// DeleteReportByID deletes a specific report by report id.
func DeleteReportByID(id int64) error {
	if tmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := tmgr.db.Exec(sqlDeleteReportByID, id)
	if err != nil {
		return err
	}
	return nil
}

// FindBaseValuesByClientID returns all base values by a specific client id.
func FindBaseValuesByClientID(id int64) ([]typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindBaseValuesByClientID, id)
	if err != nil {
		return nil, err
	}
	basevalues := make([]typdefs.BaseRow, 0, 20)
	for rows.Next() {
		res := typdefs.BaseRow{}
		err2 := rows.Scan(&res.ID, &res.BaseType, &res.Uuid,
			&res.CreateTime, &res.Name, &res.Enabled)
		if err2 != nil {
			return nil, err2
		}
		basevalues = append(basevalues, res)
	}
	return basevalues, nil
}

// FindHostBaseValuesByClientID returns all hostbase values by a specific client id.
func FindHostBaseValuesByClientID(id int64) ([]*typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindHostBaseValuesByClientID, id)
	if err != nil {
		return nil, err
	}
	basevalues := make([]*typdefs.BaseRow, 0, 20)
	for rows.Next() {
		res := typdefs.BaseRow{}
		err2 := rows.Scan(&res.ID, &res.ClientID, &res.BaseType, &res.Uuid,
			&res.CreateTime, &res.Name, &res.Enabled, &res.Pcr, &res.Bios, &res.Ima)
		if err2 != nil {
			return nil, err2
		}
		basevalues = append(basevalues, &res)
	}
	return basevalues, nil
}

// FindContainerBaseValuesByClientID returns all containerbase values by a specific client id.
func FindContainerBaseValuesByClientID(id int64) ([]*typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindContainerBaseValuesByClientID, id)
	if err != nil {
		return nil, err
	}
	basevalues := make([]*typdefs.BaseRow, 0, 20)
	for rows.Next() {
		res := typdefs.BaseRow{}
		err2 := rows.Scan(&res.ID, &res.ClientID, &res.BaseType, &res.Uuid,
			&res.CreateTime, &res.Name, &res.Enabled, &res.Pcr, &res.Bios, &res.Ima)
		if err2 != nil {
			return nil, err2
		}
		basevalues = append(basevalues, &res)
	}
	return basevalues, nil
}

// FindDeviceBaseValuesByClientID returns all devicebase values by a specific client id.
func FindDeviceBaseValuesByClientID(id int64) ([]*typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindDeviceBaseValuesByClientID, id)
	if err != nil {
		return nil, err
	}
	basevalues := make([]*typdefs.BaseRow, 0, 20)
	for rows.Next() {
		res := typdefs.BaseRow{}
		err2 := rows.Scan(&res.ID, &res.ClientID, &res.BaseType, &res.Uuid,
			&res.CreateTime, &res.Name, &res.Enabled, &res.Pcr, &res.Bios, &res.Ima)
		if err2 != nil {
			return nil, err2
		}
		basevalues = append(basevalues, &res)
	}
	return basevalues, nil
}

// FindBaseValueByID returns a specific base value by base value id.
func FindBaseValueByID(id int64) (*typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	basevalue := &typdefs.BaseRow{}
	err := tmgr.db.QueryRow(sqlFindBaseValueByID, id).Scan(&basevalue.ID,
		&basevalue.ClientID, &basevalue.BaseType, &basevalue.Uuid, &basevalue.CreateTime, &basevalue.Name,
		&basevalue.Enabled, &basevalue.Pcr, &basevalue.Bios, &basevalue.Ima)
	if err != nil {
		return nil, err
	}
	return basevalue, nil
}

// FindBaseValueByUuid returns a specific base value by base value uuid.
func FindBaseValueByUuid(uuid string) (*typdefs.BaseRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	basevalue := &typdefs.BaseRow{}
	err := tmgr.db.QueryRow(sqlFindBaseValueByUuid, uuid).Scan(&basevalue.ID,
		&basevalue.ClientID, &basevalue.BaseType, &basevalue.Uuid, &basevalue.CreateTime, &basevalue.Name,
		&basevalue.Enabled, &basevalue.Pcr, &basevalue.Bios, &basevalue.Ima)
	if err != nil {
		return nil, err
	}
	return basevalue, nil
}

// DeleteBaseValueByID deletes a specific base value by base value id.
func DeleteBaseValueByID(id int64) error {
	if tmgr == nil {
		return typdefs.ErrParameterWrong
	}
	_, err := tmgr.db.Exec(sqlDeleteBaseValueByID, id)
	if err != nil {
		return err
	}
	return nil
}

// HandleHeartbeat handles the heat beat request, update client cache and reply some commands.
func HandleHeartbeat(id int64) (uint64, uint64) {
	c, err := GetCache(id)
	if err != nil {
		return typdefs.CmdNone, 0
	}
	c.UpdateHeartBeat(config.GetHBDuration())
	c.UpdateOnline(config.GetOnlineDuration())
	cmd := c.GetCommands()
	nonce := c.GetNonce()
	c.ClearCommands()
	return cmd, nonce
}

// ValidateReport validates the report and returns the result.
// use the short broken algorithm once one part doesn't match base.
func ValidateReport(report *typdefs.TrustReport) (bool, error) {
	c, err := GetCache(report.ClientID)
	if err != nil {
		return false, err
	}
	// 1. use cache to check Nonce value.
	if !c.CompareNonce(report.Nonce) {
		c.SetTrusted(cache.StrUntrusted)
		return false, typdefs.ErrNonceNotMatch
	}
	row := &typdefs.ReportRow{
		ClientID:   report.ClientID,
		CreateTime: time.Now(),
	}
	// 2. check the Quoted/Signature
	_, err = checkQuote(c, report, row)
	if err != nil {
		c.SetTrusted(cache.StrUntrusted)
		return false, err
	}
	// 3. check pcr log
	_, err = checkPcrLog(report, row)
	if err != nil {
		c.SetTrusted(cache.StrUntrusted)
		return false, err
	}
	// 4. check bios and ima log
	_, err = checkBiosAndImaLog(report, row)
	if err != nil {
		c.SetTrusted(cache.StrUntrusted)
		return false, err
	}
	row.Validated = true
	row.Trusted = true
	c.SetTrusted(cache.StrTrusted)
	c.UpdateTrustReport(config.GetTrustDuration())
	go pushToStorePipe(row)
	return true, nil
}

func checkQuote(c *cache.Cache, report *typdefs.TrustReport, row *typdefs.ReportRow) (bool, error) {
	if len(report.Quoted) == 0 || len(report.Signature) == 0 {
		return false, typdefs.ErrParameterWrong
	}
	signature := new(tpm2.Signature)
	err := json.Unmarshal(report.Signature, signature)
	if err != nil {
		return false, err
	}

	/*alg := config.GetDigestAlgorithm()
	h, err := typdefs.GetHFromAlg(alg)
	if err != nil {
		return false, err
	}*/
	h := sha256.New()
	h.Write(report.Quoted)
	datahash := h.Sum(nil)
	ikCert := c.GetIKeyCert()
	if ikCert == nil {
		return false, typdefs.ErrIKCertNull
	}
	/*
		switch alg {
		case typdefs.Sha1AlgStr:
			err = rsa.VerifyPKCS1v15(ikCert.PublicKey.(*rsa.PublicKey),
				crypto.SHA1, datahash, signature.RSA.Signature)
		case typdefs.Sha256AlgStr:
			err = rsa.VerifyPKCS1v15(ikCert.PublicKey.(*rsa.PublicKey),
				crypto.SHA256, datahash, signature.RSA.Signature)
		case typdefs.Sm3AlgStr:
			// set hash parameter 0 because sm3 is not supported in crypto package
			err = rsa.VerifyPKCS1v15(ikCert.PublicKey.(*rsa.PublicKey),
				0, datahash, signature.RSA.Signature)
		default:
			return false, typdefs.ErrNotSupportAlg
		}*/
	err = rsa.VerifyPKCS1v15(ikCert.PublicKey.(*rsa.PublicKey),
		crypto.SHA256, datahash, signature.RSA.Signature)
	if err != nil {
		return false, err
	}
	row.Signature = string(report.Signature)
	row.Quoted = hex.EncodeToString(report.Quoted)
	return true, nil
}

func pcrLogToMap(pcrLog []byte) map[int]string {
	m := make(map[int]string, typdefs.PcrMaxNum)
	lines := bytes.Split(pcrLog, typdefs.NewLine)
	for _, line := range lines {
		words := bytes.Split(line, typdefs.Space)
		if len(words) == 3 {
			i, err := strconv.Atoi(string(words[2]))
			if err == nil {
				m[i] = string(words[0])
			}
		}
		if len(words) == 2 {
			i, err := strconv.Atoi(string(words[0]))
			if err == nil {
				m[i] = string(words[1])
			}
		}
	}
	return m
}

func checkPcrLog(report *typdefs.TrustReport, row *typdefs.ReportRow) (bool, error) {
	pcrLog := findManifest(report, typdefs.StrPcr)
	pcrMap := pcrLogToMap(pcrLog)
	//use PCRselection to calculate PCRdigest
	parsedQuote, err := tpm2.DecodeAttestationData(report.Quoted)
	if err != nil {
		return false, err
	}
	//combine all pcrs
	temp := []byte{}
	for _, PCRid := range parsedQuote.AttestedQuoteInfo.PCRSelection.PCRs {
		pcrValueBytes, err2 := hex.DecodeString(pcrMap[PCRid])
		if err2 != nil {
			return false, err
		}
		temp = append(temp, pcrValueBytes...)
	}
	//calculate new pcr digest
	/*alg := config.GetDigestAlgorithm()
	h1, err := typdefs.GetHFromAlg(alg)
	if err != nil {
		return false, err
	}*/
	h1 := sha256.New()
	h1.Write(temp)
	newDigestBytes := h1.Sum(nil)
	if !bytes.Equal(newDigestBytes, parsedQuote.AttestedQuoteInfo.PCRDigest) {
		return false, typdefs.ErrPCRNotMatch
	}
	row.PcrLog = string(pcrLog)
	return true, nil
}

func findManifest(report *typdefs.TrustReport, key string) []byte {
	for _, m := range report.Manifests {
		if m.Key == key {
			return m.Value
		}
	}
	return []byte{}
}

//??????bios???imaLog??????pcr?????????bios???ima??????cache???
func checkBiosAndImaLog(report *typdefs.TrustReport, row *typdefs.ReportRow) (bool, error) {
	bLog := findManifest(report, typdefs.StrBios)
	btLog, _ := typdefs.TransformBIOSBinLogToTxt(bLog)
	pcrs := typdefs.NewPcrGroups()
	typdefs.ExtendPCRWithBIOSTxtLog(pcrs, btLog)
	imaLog := findManifest(report, typdefs.StrIma)
	row.BiosLog = string(btLog)
	row.ImaLog = string(imaLog)
	pcrLog := findManifest(report, typdefs.StrPcr)
	pcrMap := pcrLogToMap(pcrLog)
	err := typdefs.AddPcr8And9FromPcrMap(pcrs, pcrMap, config.GetDigestAlgorithm())
	if err != nil {
		return false, err
	}
	return typdefs.ExtendPCRWithIMALog(pcrs, imaLog, config.GetDigestAlgorithm())
}

func HandleBaseValue(report *typdefs.TrustReport) error {
	// if this client's AutoUpdate is true, save base value of rac which in the update list
	if tmgr.cache[report.ClientID].GetIsAutoUpdate() {
		{
			tmgr.cache[report.ClientID].SetIsAutoUpdate(false)
			ModifyEnabledByClientID(report.ClientID)
			err := recordAutoUpdateReport(report)
			if err != nil {
				return err
			}
		}
	} else {
		switch config.GetMgrStrategy() {
		case config.AutoStrategy:
			// if this client's AutoUpdate is false, and if this is the first report of this RAC, extract base value
			isFirstReport, err := isFirstReport(report.ClientID)
			if err != nil {
				return err
			}
			if isFirstReport {
				// this is first report, so oldBase is nil
				baseValue := typdefs.BaseRow{
					ClientID: report.ClientID,
					Enabled:  false,
					Verified: false,
					Trusted:  false,
				}
				err = extract(report, nil, &baseValue)
				if err != nil {
					return err
				}
				tmgr.cache[report.ClientID].SetTrusted(cache.StrTrusted)
				baseValue.CreateTime = time.Now()
				baseValue.BaseType = typdefs.StrHost
				SaveBaseValue(&baseValue)
			} else {
				verifyReport(report)
			}
		case config.ManualStrategy:
			verifyReport(report)
		}
	}

	return nil
}

// Traverse the base values ??????in the cache and compare with report,
// save the result in the cache
func verifyReport(report *typdefs.TrustReport) {
	var hasEnabled bool = false
	trusted := cache.StrTrusted
	for _, base := range tmgr.cache[report.ClientID].HostBases {
		if base.Enabled {
			hasEnabled = true
			err := Verify(base, report)
			base.Verified = true
			if err != nil {
				base.Trusted = false
				trusted = cache.StrUntrusted
			} else {
				base.Trusted = true
			}
		}
	}
	if !hasEnabled {
		trusted = cache.StrUnknown
	}
	tmgr.cache[report.ClientID].SetTrusted(trusted)
}

func recordAutoUpdateReport(report *typdefs.TrustReport) error {

	c, err := GetCache(report.ClientID)
	if err != nil {
		return err
	}
	bases := c.HostBases
	newBase := typdefs.BaseRow{
		ClientID:   report.ClientID,
		CreateTime: time.Now(),
		Enabled:    true,
		Verified:   true,
		Trusted:    true,
		BaseType:   typdefs.StrHost,
	}
	// If the client's basevalue exists in the cache,
	// the extraction template is consistent with the old.
	// Otherwise, read extraction template from config.
	extractReportFromOldBases(bases, &newBase, report)
	c.SetTrusted(cache.StrTrusted)

	return nil
}

func extractReportFromOldBases(bases []*typdefs.BaseRow, newBase *typdefs.BaseRow, report *typdefs.TrustReport) error {
	hasEnabled := false
	for _, oldBase := range bases {
		if oldBase.Enabled {
			hasEnabled = true
			oldBase.Enabled = false
			ModifyEnabledByID(oldBase.ID)
			err := extract(report, oldBase, newBase)
			if err != nil {
				return err
			}
			if isBaseUpdate(oldBase, newBase) {
				SaveBaseValue(newBase)
			}
		}
	}
	if !hasEnabled {
		oldBase := typdefs.EmptyBase
		err := extract(report, &oldBase, newBase)
		if err != nil {
			return err
		}
		if isBaseUpdate(&oldBase, newBase) {
			SaveBaseValue(newBase)
		}
	}
	return nil
}

func isBaseUpdate(oldBase *typdefs.BaseRow, newBase *typdefs.BaseRow) bool {
	// compare pcr
	if oldBase.Pcr != newBase.Pcr {
		return true
	}
	// compare bios
	if oldBase.Bios != newBase.Bios {
		return true
	}
	// compare ima
	if oldBase.Ima != newBase.Ima {
		return true
	}
	return false
}

func isFirstReport(clientId int64) (bool, error) {
	if tmgr == nil {
		return false, typdefs.ErrParameterWrong
	}
	rows, err := tmgr.db.Query(sqlFindReportsByClientID, clientId)
	if err != nil {
		return false, err
	}
	// because isFirstReport is judged after saving report, len(rows) == 1
	if !rows.Next() {
		return true, nil
	}

	return false, nil
}

func extract(report *typdefs.TrustReport, oldBase, newBase *typdefs.BaseRow) error {

	newBase.Pcr = extractPCR(report, oldBase)
	newBase.Bios = extractBIOS(report, oldBase)
	newBase.Ima = extractIMA(report, oldBase)
	return nil
}

func Verify(baseValue *typdefs.BaseRow, report *typdefs.TrustReport) error {

	if err := verifyPCR(report, baseValue); err != nil {
		return fmt.Errorf("pcr manifest verification failed, error: %s", err)
	}
	if err := verifyBIOS(report, baseValue); err != nil {
		return fmt.Errorf("bios manifest verification failed, error: %s", err)
	}
	if err := verifyIMA(report, baseValue); err != nil {
		return fmt.Errorf("ima manifest verification failed, error: %s", err)
	}

	return nil
}

func GetExtractRulesFromPcr(pcrlog string) []int {
	res := []int{}
	lines := bytes.Split([]byte(pcrlog), typdefs.NewLine)
	if l := len(lines); l > 0 && len(lines[l-1]) == 0 {
		lines = lines[:l-1]
	}
	for _, line := range lines {
		v, _ := strconv.Atoi(string(line[0]))
		res = append(res, v)
	}
	return res
}

func extractPCR(report *typdefs.TrustReport, base *typdefs.BaseRow) string {
	pcrLog := findManifest(report, typdefs.StrPcr)
	pcrMap := pcrLogToMap(pcrLog)
	pcrSelection := config.GetExtractRules().PcrRule.PcrSelection
	// if oldBase exist, extractRules are consistent with it
	if base != nil && *base != typdefs.EmptyBase {
		pcrSelection = GetExtractRulesFromPcr(base.Pcr)
	}

	var buf bytes.Buffer
	for _, n := range pcrSelection {
		if v, ok := pcrMap[n]; ok {
			buf.WriteString(fmt.Sprintf("%d %s\n", n, v))
		}
	}
	return buf.String()
}

func verifyPCR(report *typdefs.TrustReport, base *typdefs.BaseRow) error {
	pcrLog := findManifest(report, typdefs.StrPcr)
	rPcrMap := pcrLogToMap(pcrLog)
	bPcrMap := pcrLogToMap([]byte(base.Pcr))

	for i, s := range bPcrMap {
		if s != rPcrMap[i] {
			return fmt.Errorf("pcr %d not equal", i)
		}
	}
	return nil
}

// The bios string in BaseRow has the following fields, separated by space:
//   column 1: hash type
//	 column 2: filedata-hash
// 	 column 3: filename-hint
func extractBIOS(report *typdefs.TrustReport, base *typdefs.BaseRow) string {
	biosNames := getBiosExtractTemplate(base)
	used := make([]bool, len(biosNames))
	var buf bytes.Buffer
	// reset manifest to append extract result
	bLog := findManifest(report, typdefs.StrBios)
	btLog, _ := typdefs.TransformBIOSBinLogToTxt(bLog)
	lines := bytes.Split(btLog, typdefs.NewLine)
	for _, ln := range lines {
		words := bytes.Split(ln, typdefs.Space)
		for i, bn := range biosNames {
			if used[i] {
				continue
			}
			if bn == string(words[2]) {
				used[i] = true
				buf.WriteString(bn) //name sha1Hash sha256:sha256Hash sm3:sm3Hash
				buf.WriteString(" " + string(words[3]))
				if len(words) >= 5 {
					buf.WriteString(" " + string(words[4]))
				} else {
					buf.WriteString(" N/A")
				}
				if len(words) >= 6 {
					buf.WriteString(" " + string(words[5]))
				} else {
					buf.WriteString(" N/A")
				}
				buf.WriteString("\n")
				break
			}
		}
	}
	return buf.String()
}

// There are multiple situations
// bios may have one to three type of hash : sha1 sha256 sm3;  sha1 sha256 N/A;  N/A sha256 sm3; ...
// There are four cases of return value:
// 			0: means no errors
// 			1: means their sha1 hash not equal
// 			2: means their second hash not equal
// 			3: means their third hash not equal
// 			-1: means their hash type not equal, can't verify
func compareBiosHash(words1, words2 [][]byte) int {
	if string(words1[3]) != "N/A" && string(words2[1]) != "N/A" {
		// if both base and report have sha1 hash in bios, return the result of their comparison
		if bytes.Equal(words1[3], words2[1]) {
			return 0
		} else {
			return 1
		}

	}
	if string(words1[4]) != "N/A" && string(words2[2]) != "N/A" {
		// if both base and report have sha256 hash in bios, return the result of their comparison
		if bytes.Equal(words1[4], words2[2]) {
			return 0
		} else {
			return 2
		}

	}
	if string(words1[5]) != "N/A" && string(words2[3]) != "N/A" {
		// if both base and report have sm3 hash in bios, return the result of their comparison
		if bytes.Equal(words1[5], words2[3]) {
			return 0
		} else {
			return 3
		}

	}
	// if there are no same type of hash in bios, return -1
	return -1
}

func verifyBIOS(report *typdefs.TrustReport, base *typdefs.BaseRow) error {
	bLog := findManifest(report, typdefs.StrBios)
	btLog1, _ := typdefs.TransformBIOSBinLogToTxt(bLog)
	btLog2 := ([]byte)(base.Bios)
	lines1 := bytes.Split(btLog1, typdefs.NewLine)
	lines2 := bytes.Split(btLog2, typdefs.NewLine)
	if l := len(lines1); l > 0 && len(lines1[l-1]) == 0 {
		lines1 = lines1[:l-1]
	}
	if l := len(lines2); l > 0 && len(lines2[l-1]) == 0 {
		lines2 = lines2[:l-1]
	}
	used := make([]bool, len(lines2))
	for _, ln1 := range lines1 {
		words1 := bytes.Split(ln1, typdefs.Space)
		for i, ln2 := range lines2 {
			if used[i] {
				continue
			}
			words2 := bytes.Split(ln2, typdefs.Space)
			if bytes.Equal(words1[2], words2[0]) {
				used[i] = true
				res := compareBiosHash(words1, words2)
				switch res {
				case 0:
					continue
				case 1:
					return fmt.Errorf("%s sha1 hash not equal", string(words1[2]))
				case 2:
					return fmt.Errorf("%s sha256 hash not equal", string(words1[2]))
				case 3:
					return fmt.Errorf("%s sm3 hash not equal", string(words1[2]))
				case -1:
					return fmt.Errorf("there are no the same type of hash")
				}
			}
		}
	}
	return nil
}

func GetExtractRulesFromBios(bioslog string) []string {
	var biosNames []string
	lines := bytes.Split([]byte(bioslog), typdefs.NewLine)
	if l := len(lines); l > 0 && len(lines[l-1]) == 0 {
		lines = lines[:l-1]
	}
	for _, ln := range lines {
		words := bytes.Split(ln, typdefs.Space)
		biosNames = append(biosNames, string(words[0]))
	}
	return biosNames
}

func getBiosExtractTemplate(oldBase *typdefs.BaseRow) []string {
	var biosNames []string
	// if oldBase exist, extractRules are consistent with it
	if oldBase != nil && *oldBase != typdefs.EmptyBase {
		biosNames = GetExtractRulesFromBios(oldBase.Bios)
	} else {
		mRule := config.GetExtractRules().ManifestRules
		for _, rule := range mRule {
			if strings.ToLower(rule.MType) == typdefs.StrBios {
				biosNames = rule.Name
				break
			}
		}
	}

	return biosNames
}

func GetExtractRulesFromIma(imalog string) []string {
	var imaNames []string
	lines := bytes.Split([]byte(imalog), typdefs.NewLine)
	if l := len(lines); l > 0 && len(lines[l-1]) == 0 {
		lines = lines[:l-1]
	}
	for _, ln := range lines {
		words := bytes.Split(ln, typdefs.Space)
		imaNames = append(imaNames, string(words[2]))
	}
	return imaNames
}

func getIMAExtractTemplate(oldBase *typdefs.BaseRow) []string {
	var imaNames []string
	// if oldBase exist, extractRules are consistent with it
	if oldBase != nil && *oldBase != typdefs.EmptyBase {
		imaNames = GetExtractRulesFromIma(oldBase.Ima)
	} else {
		for _, rule := range config.GetExtractRules().ManifestRules {
			if strings.ToLower(rule.MType) == typdefs.StrIma {
				imaNames = rule.Name
				break
			}
		}
	}

	return imaNames
}

// The ima string in BaseRow has the following fields, separated by space:
//   column 1: hash type
//	 column 2: filedata-hash
// 	 column 3: filename-hint
func extractIMA(report *typdefs.TrustReport, base *typdefs.BaseRow) string {
	imaNames := getIMAExtractTemplate(base)
	used := make([]bool, len(imaNames))
	var buf bytes.Buffer
	// reset manifest to append extract result
	imaLog := findManifest(report, typdefs.StrIma)
	lines := bytes.Split(imaLog, typdefs.NewLine)
	for _, ln := range lines {
		words := bytes.Split(ln, typdefs.Space)
		for i, in := range imaNames {
			if used[i] {
				continue
			}
			if string(words[4]) == in {
				used[i] = true
				buf.WriteString(string(words[2]) + " ")
				buf.WriteString(string(words[3]) + " ")
				buf.WriteString(string(words[4]))
				buf.WriteString("\n")
				break
			}
		}
	}
	return buf.String()
}

func verifyIMA(report *typdefs.TrustReport, base *typdefs.BaseRow) error {
	imaLog1 := findManifest(report, typdefs.StrIma)
	imaLog2 := []byte(base.Ima)
	lines1 := bytes.Split(imaLog1, typdefs.NewLine)
	lines2 := bytes.Split(imaLog2, typdefs.NewLine)
	if l := len(lines1); l > 0 && len(lines1[l-1]) == 0 {
		lines1 = lines1[:l-1]
	}
	if l := len(lines2); l > 0 && len(lines2[l-1]) == 0 {
		lines2 = lines2[:l-1]
	}
	used := make([]bool, len(lines2))
	for _, ln1 := range lines1 {
		words1 := bytes.Split(ln1, typdefs.Space)
		for i, ln2 := range lines2 {
			if used[i] {
				continue
			}
			words2 := bytes.Split(ln2, typdefs.Space)
			if bytes.Equal(words1[4], words2[2]) {
				used[i] = true
				if !bytes.Equal(words1[3], words2[1]) {
					return fmt.Errorf("%s hash not equal", string(words1[4]))
				}
			}
		}
	}
	return nil
}

const (
	maxStoreWorker = 20
)

var (
	dbIndex int64              = 0
	chDb    []chan interface{} = nil
	storeDb *sql.DB            = nil
)

func createStorePipe(dbType, dbConfig string) {
	var err error
	if storeDb != nil {
		return
	}
	storeDb, err = sql.Open(dbType, dbConfig)
	if err != nil {
		storeDb = nil
		return
	}
	chDb = make([]chan interface{}, maxStoreWorker)
	for i := 0; i < maxStoreWorker; i++ {
		chDb[i] = make(chan interface{})
		go handleStorePipe(i)
	}
}

func releaseStorePipe() {
	if chDb != nil {
		for i := 0; i < maxStoreWorker; i++ {
			close(chDb[i])
			chDb[i] = nil
		}
		chDb = nil
	}
	if storeDb != nil {
		storeDb.Close()
		storeDb = nil
	}
}

func pushToStorePipe(v interface{}) {
	if chDb != nil {
		i := atomic.AddInt64(&dbIndex, 1)
		i = i % maxStoreWorker
		chDb[i] <- v
	}
}

func SaveBaseValue(row *typdefs.BaseRow) {
	go pushToStorePipe(row)
}

func handleStorePipe(i int) {
	for {
		if chDb == nil {
			return
		}
		em := <-chDb[i]
		if storeDb == nil {
			return
		}
		switch v := em.(type) {
		case *typdefs.ReportRow:
			res, err := storeDb.Exec(sqlInsertTrustReport,
				v.ClientID, v.CreateTime, v.Validated, v.Trusted,
				v.Quoted, v.Signature, v.PcrLog, v.BiosLog, v.ImaLog)
			if err != nil {
				logger.L.Sugar().Errorf("insert trust report error, result %v, %v", res, err)
			}
		case *typdefs.BaseRow:
			// ????????????????????????????????????????????????????????????????????????????????????????????????cache???
			// ??????clientID?????????client???????????????????????????????????????????????????
			// ????????????????????????????????????cache???????????????????????????????????????
			res, err := storeDb.Exec(sqlInsertBase, v.ClientID, v.BaseType, v.Uuid, v.CreateTime,
				v.Enabled, v.Name, v.Pcr, v.Bios, v.Ima)
			if err != nil {
				logger.L.Sugar().Errorf("insert base error, result %v, %v", res, err)
			}
			if tmgr.cache[v.ClientID] == nil {
				continue
			}
			switch v.BaseType {
			case typdefs.StrHost:
				tmgr.cache[v.ClientID].HostBases = append(tmgr.cache[v.ClientID].HostBases, v)
			case typdefs.StrContainer:
				for i, base := range tmgr.cache[v.ClientID].ContainerBases {
					if base.Uuid == v.Uuid {
						tmgr.cache[v.ClientID].ContainerBases[i] = v
					}
				}
			case typdefs.StrDevice:
				for i, base := range tmgr.cache[v.ClientID].DeviceBases {
					if base.Uuid == v.Uuid {
						tmgr.cache[v.ClientID].DeviceBases[i] = v
						break
					}
				}
			}
		}
	}
}
