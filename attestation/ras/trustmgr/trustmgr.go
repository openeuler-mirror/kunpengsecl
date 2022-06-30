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
	"sort"
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
	sqlRegisterClientByIK       = `INSERT INTO client(regtime, deleted, info, ikcert) VALUES ($1, $2, $3, $4) RETURNING id`
	sqlFindAllEnabledClients    = `SELECT id, regtime, ikcert FROM client WHERE deleted=false`
	sqlFindClientByID           = `SELECT regtime, deleted, info, ikcert FROM client WHERE id=$1`
	sqlFindClientIDByIK         = `SELECT id FROM client WHERE ikcert=$1`
	sqlFindClientFullByIK       = `SELECT id, regtime, deleted, info FROM client WHERE ikcert=$1`
	sqlFindClientsByInfo        = `SELECT id, regtime, deleted, info, ikcert FROM client WHERE info @> $1`
	sqlFindReportsByClientID    = `SELECT id, clientid, createtime, validated, trusted FROM report WHERE clientid=$1 ORDER BY createtime ASC`
	sqlFindReportByID           = `SELECT id, clientid, createtime, validated, trusted, quoted, signature, pcrlog, bioslog, imalog FROM report WHERE id=$1`
	sqlFindBaseValuesByClientID = `SELECT id, basetype, uuid, createtime, name, enabled FROM base WHERE clientid=$1 ORDER BY createtime ASC`
	sqlFindBaseValueByID        = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE id=$1`
	sqlFindBaseValueByUuid      = `SELECT id, clientid, basetype, uuid, createtime, name, enabled, pcr, bios, ima FROM base WHERE uuid=$1`
	sqlDeleteReportByID         = `DELETE FROM report WHERE id=$1`
	sqlDeleteBaseValueByID      = `DELETE FROM base WHERE id=$1`
	sqlUnRegisterClientByID     = `UPDATE client SET deleted=true WHERE id=$1`
	sqlUpdateClientByID         = `UPDATE client SET info=$2 WHERE id=$1`
	sqlInsertTrustReport        = `INSERT INTO report(clientid, createtime, validated, trusted, quoted, signature, pcrlog, bioslog, imalog) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	sqlInsertBase               = `INSERT INTO base(clientid, basetype, uuid, createtime, enabled, name, pcr, bios, ima) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
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
func GetAllNodes(f, t int64) (typdefs.ArrNodeInfo, error) {
	var nodes typdefs.ArrNodeInfo
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	tmgr.mu.Lock()
	defer tmgr.mu.Unlock()
	for i, v := range tmgr.cache {
		if f <= i && i < t {
			n := typdefs.NodeInfo{
				ID:      i,
				RegTime: v.GetRegTime(),
				Online:  v.GetOnline(),
				Trusted: v.GetTrusted(),
			}
			nodes = append(nodes, n)
		}
	}
	sort.Sort(nodes)
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

// RegisterClientByIK registers a new client by ikCert and info. if there is a existing ik, register will fail.
func RegisterClientByIK(ikCert, info string) (*typdefs.ClientRow, error) {
	if tmgr == nil {
		return nil, typdefs.ErrParameterWrong
	}
	c := typdefs.ClientRow{IKCert: ikCert}
	err := tmgr.db.QueryRow(sqlFindClientIDByIK, ikCert).Scan(&c.ID)
	if err == nil {
		return nil, typdefs.ErrAlreadyRegistered
	}
	c = typdefs.ClientRow{
		RegTime: time.Now(),
		Deleted: false,
		Info:    info,
		IKCert:  ikCert,
	}
	err = tmgr.db.QueryRow(sqlRegisterClientByIK, c.RegTime,
		c.Deleted, c.Info, c.IKCert).Scan(&c.ID)
	if err != nil {
		return nil, err
	}
	ca := cache.NewCache()
	ca.SetRegTime(c.RegTime.Format(typdefs.StrTimeFormat))
	ca.SetIKeyCert(ikCert)
	tmgr.mu.Lock()
	tmgr.cache[c.ID] = ca
	tmgr.mu.Unlock()
	return &c, nil
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
		&c.RegTime, &c.Deleted, &c.Info)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// FindClientByID gets client from database by id.
func FindClientByID(id int64) (*typdefs.ClientRow, error) {
	_, err := GetCache(id)
	if err != nil {
		return nil, err
	}
	c := typdefs.ClientRow{ID: id}
	err = tmgr.db.QueryRow(sqlFindClientByID, id).Scan(&c.RegTime,
		&c.Deleted, &c.Info, &c.IKCert)
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
		err2 := rows.Scan(&c.ID, &c.RegTime, &c.Deleted, &c.Info, &c.IKCert)
		if err2 != nil {
			return nil, err2
		}
		cs = append(cs, c)
	}
	return cs, nil
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
func HandleHeartbeat(id int64) (uint64, uint64, error) {
	c, err := GetCache(id)
	if err != nil {
		return 0, 0, err
	}
	c.UpdateHeartBeat(config.GetHBDuration(), config.GetTrustDuration())
	cmd := c.GetCommands()
	nonce := c.GetNonce()
	c.ClearCommands()
	return cmd, nonce, nil
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
		return false, typdefs.ErrNonceNotMatch
	}
	row := &typdefs.ReportRow{
		ClientID:   report.ClientID,
		CreateTime: time.Now(),
	}
	// 2. check the Quoted/Signature
	_, err = checkQuote(c, report, row)
	if err != nil {
		return false, err
	}
	// 3. check pcr log
	_, err = checkPcrLog(report, row)
	if err != nil {
		return false, err
	}
	// 4. check bios and ima log
	_, err = checkBiosAndImaLog(report, row)
	if err != nil {
		return false, err
	}
	row.Validated = true
	row.Trusted = true
	c.SetTrusted(true)
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
	h := sha256.New()
	h.Write(report.Quoted)
	datahash := h.Sum(nil)
	ikCert := c.GetIKeyCert()
	if ikCert == nil {
		return false, typdefs.ErrIKCertNull
	}
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

//根据bios和imaLog扩展pcr并且把bios和ima存到cache中
func checkBiosAndImaLog(report *typdefs.TrustReport, row *typdefs.ReportRow) (bool, error) {
	bLog := findManifest(report, typdefs.StrBios)
	btLog, _ := typdefs.TransformBIOSBinLogToTxt(bLog)
	pcrs := typdefs.NewPcrGroups()
	typdefs.ExtendPCRWithBIOSTxtLog(pcrs, btLog)
	imaLog := findManifest(report, typdefs.StrIma)
	row.BiosLog = string(btLog)
	row.ImaLog = string(imaLog)
	return typdefs.ExtendPCRWithIMALog(pcrs, imaLog)
}

func HandleBaseValue(report *typdefs.TrustReport) error {
	// if this client's AutoUpdate is true, save base value of rac which in the update list
	if tmgr.cache[report.ClientID].GetIsAutoUpdate() {
		{
			err := recordAutoUpdateReport(report)
			if err != nil {
				return err
			}
		}
	} else {
		// if this client's AutoUpdate is false, and if this is the first report of this RAC, extract base value
		isFirstReport, err := isFirstReport(report.ClientID)
		if err != nil {
			return err
		}
		baseValue := typdefs.BaseRow{}
		if isFirstReport {
			err = extract(report, &baseValue)
			if err != nil {
				return err
			}
			// TODO:1.保证一个ClientID的基准值同时只有一个Enabled=TRUE
			// 2.完善Name字段
			baseValue.ClientID = report.ClientID
			baseValue.CreateTime = time.Now()
			baseValue.Enabled = false
			baseValue.Verified = false
			baseValue.Trusted = false
			SaveBaseValue(&baseValue)
		}
	}
	return nil
}

func recordAutoUpdateReport(report *typdefs.TrustReport) error {
	if isClientAutoUpdate(report.ClientID) {
		historyBase, err := FindBaseValuesByClientID(report.ClientID)
		if err != nil {
			return err
		}
		newBase := typdefs.BaseRow{}
		oldBase := typdefs.BaseRow{}
		// 如果该client已经存在基准值，则后续的抽取模板和存在的基准值保持一致，
		// 否则，抽取模板从config读取
		if len(historyBase) != 0 {
			oldBase = historyBase[len(historyBase)-1]
			newBase = typdefs.BaseRow{
				ClientID: report.ClientID,
			}
		}
		err = extract(report, &newBase)
		if err != nil {
			return err
		}
		// TODO:1.保证一个ClientID的基准值同时只有一个Enabled=TRUE
		// 2.完善Name字段
		if isBaseUpdate(&oldBase, &newBase) {
			newBase.ClientID = report.ClientID
			newBase.CreateTime = time.Now()
			newBase.Enabled = false
			newBase.Verified = false
			newBase.Trusted = false
			SaveBaseValue(&newBase)
		}
	}
	return nil
}

func isClientAutoUpdate(clientID int64) bool {
	// if all update
	if config.GetAutoUpdateConfig().IsAllUpdate {
		return true
	}
	clients := config.GetAutoUpdateConfig().UpdateClients
	for _, c := range clients {
		if clientID == c {
			return true
		}
	}
	return false
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

func extract(report *typdefs.TrustReport, basevalue *typdefs.BaseRow) error {
	//pcr抽取
	err := extractPCR(report, basevalue)
	if err != nil {
		return err
	}
	//bios抽取
	err = extractBIOS(report, basevalue)
	if err != nil {
		return err
	}
	//ima抽取
	err = extractIMA(report, basevalue)
	if err != nil {
		return err
	}

	return nil
}

func Verify(baseValue *typdefs.BaseRow, report *typdefs.TrustReport) error {
	newBaseValue := typdefs.BaseRow{
		ClientID: report.ClientID,
	}
	err := extractBIOS(report, &newBaseValue)
	if err != nil {
		return err
	}
	if baseValue.Pcr != newBaseValue.Pcr {
		return fmt.Errorf("pcr manifest verification failed")
	}
	if baseValue.Bios != newBaseValue.Bios {
		return fmt.Errorf("bios manifest verification failed")
	}
	if baseValue.Ima != newBaseValue.Ima {
		return fmt.Errorf("ima manifest verification failed")
	}

	return nil
}

func extractPCR(report *typdefs.TrustReport, mInfo *typdefs.BaseRow) error {
	pcrLog := findManifest(report, typdefs.StrPcr)
	pcrMap := pcrLogToMap(pcrLog)
	pcrSelection := config.GetExtractRules().PcrRule.PcrSelection
	var buf bytes.Buffer
	for _, n := range pcrSelection {
		if v, ok := pcrMap[n]; ok {
			buf.WriteString(v)
			buf.WriteString("\n")
		} else {
			return fmt.Errorf("extract failed. pcr number %v doesn't exist in this report", n)
		}
	}
	mInfo.Pcr = buf.String()
	return nil
}

func extractBIOS(report *typdefs.TrustReport, mInfo *typdefs.BaseRow) error {
	biosNames := getBiosExtractTemplate(mInfo)
	var buf bytes.Buffer
	// reset manifest to append extract result
	bLog := findManifest(report, typdefs.StrBios)
	btLog, _ := typdefs.TransformBIOSBinLogToTxt(bLog)
	lines := bytes.Split(btLog, typdefs.NewLine)
	for _, bn := range biosNames {
		isFound := false
		for _, ln := range lines {
			words := bytes.Split(ln, typdefs.Space)
			if bn == string(words[2]) {
				isFound = true
				buf.WriteString(bn + " ") //name sha1Hash sha256:sha256Hash
				buf.WriteString(string(words[3]) + " ")
				buf.WriteString(string(words[4]))
				buf.WriteString("\n")
				break
			}
		}
		if !isFound {
			return fmt.Errorf("extract failed. bios manifest name %v doesn't exist in this report", bn)
		}
	}
	mInfo.Bios = buf.String()
	return nil
}

func getBiosExtractTemplate(mInfo *typdefs.BaseRow) []string {
	var biosNames []string
	mRule := config.GetExtractRules().ManifestRules
	if mInfo.ClientID == 0 {
		for _, rule := range mRule {
			if strings.ToLower(rule.MType) == typdefs.StrBios {
				biosNames = rule.Name
				break
			}
		}
	} else {
		lines := bytes.Split([]byte(mInfo.Bios), typdefs.NewLine)
		for _, ln := range lines {
			words := bytes.Split(ln, typdefs.Space)
			biosNames = append(biosNames, string(words[0]))
		}
	}
	return biosNames
}

func getIMAExtractTemplate(mInfo *typdefs.BaseRow) []string {
	var imaNames []string
	if mInfo.ClientID == 0 {
		for _, rule := range config.GetExtractRules().ManifestRules {
			if strings.ToLower(rule.MType) == typdefs.StrIma {
				imaNames = rule.Name
				break
			}
		}
	} else {
		lines := bytes.Split([]byte(mInfo.Ima), typdefs.NewLine)
		for _, ln := range lines {
			words := bytes.Split(ln, typdefs.Space)
			imaNames = append(imaNames, string(words[2]))
		}
	}
	return imaNames
}

func extractIMA(report *typdefs.TrustReport, mInfo *typdefs.BaseRow) error {
	imaNames := getIMAExtractTemplate(mInfo)
	var buf bytes.Buffer
	// reset manifest to append extract result
	imaLog := findManifest(report, typdefs.StrIma)
	lines := bytes.Split(imaLog, typdefs.NewLine)
	for _, in := range imaNames {
		isFound := false
		for _, line := range lines {
			words := bytes.Split(line, typdefs.Space)
			if string(words[4]) == in {
				isFound = true
				buf.WriteString(string(words[2]) + " ") //type filedata-hash filename-hint
				buf.WriteString(string(words[3]) + " ")
				buf.WriteString(string(words[4]))
				buf.WriteString("\n")
				break
			}
		}
		if !isFound {
			return fmt.Errorf("extract failed. ima manifest name %v doesn't exist in this report", in)
		}
	}
	mInfo.Ima = buf.String()
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

// 这里之前只是把新增加的基准值保存到数据库中，我觉得还要把它更新到cache中
// 根据clientID查询该client是否已经注册，如果未注册直接返回，
// 已注册则把其添加到对应的cache节点中，再存储到数据库中。
func SaveBaseValue(row *typdefs.BaseRow) {
	c := cache.NewCache()
	c.SetRegTime(row.CreateTime.Format(typdefs.StrTimeFormat))
	clientRow, err := FindClientByID(row.ClientID)
	if err != nil {
		logger.L.Sugar().Errorf("can't find target client")
		return
	}
	c.SetIKeyCert(clientRow.IKCert)
	tmgr.cache[row.ClientID] = c
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
			res, err := storeDb.Exec(sqlInsertBase, v.ClientID, v.BaseType, v.Uuid, v.CreateTime,
				v.Enabled, v.Name, v.Pcr, v.Bios, v.Ima)
			if err != nil {
				logger.L.Sugar().Errorf("insert base error, result %v, %v", res, err)
			}
		}
	}
}
