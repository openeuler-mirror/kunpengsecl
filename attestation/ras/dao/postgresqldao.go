package dao

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/jackc/pgx/v4"
)

/*
	PostgreSqlDAO implements dao.
	conn is a connection initialized in CreatePostgreSqlDAO() and destroyed in Destroy()
*/
type PostgreSqlDAO struct {
	sync.Mutex
	conn *pgx.Conn
}

const (
	sqlSelectClientInfoVerById = "SELECT client_info_ver FROM register_client WHERE id=$1"
)

// If there are name-value pairs in the clientinfo map, save them with a new clientInfoVer.
func (psd *PostgreSqlDAO) updateClientInfo(tx pgx.Tx, ctx context.Context, report *entity.Report) (clientInfoVer int, err error) {
	err = tx.QueryRow(ctx,
		sqlSelectClientInfoVerById, report.ClientID).Scan(&clientInfoVer)
	if err != nil {
		return -1, err
	}

	if len(report.ClientInfo.Info) == 0 {
		return clientInfoVer, nil
	}

	clientInfoVer++
	_, err = tx.Exec(ctx,
		"UPDATE register_client SET client_info_ver=$1 WHERE id=$2", clientInfoVer, report.ClientID)
	if err != nil {
		return clientInfoVer, err
	}

	err = psd.saveClientInfo(tx, ctx, &report.ClientInfo, report.ClientID, clientInfoVer)
	return clientInfoVer, err
}

// save report data into client_info table with clientInfoVer.
func (psd *PostgreSqlDAO) saveClientInfo(tx pgx.Tx, ctx context.Context, clientInfo *entity.ClientInfo, clientID int64, clientInfoVer int) (err error) {
	for name, value := range clientInfo.Info {
		_, err = tx.Exec(ctx,
			"INSERT INTO client_info(client_id, client_info_ver, name, value) VALUES ($1, $2, $3, $4)",
			clientID, clientInfoVer, name, value)
		if err != nil {
			return err
		}
	}

	return nil
}

// insert report data into trust_report table and return reportID
func (psd *PostgreSqlDAO) saveReportContent(tx pgx.Tx, ctx context.Context, report *entity.Report, clientInfoVer int) (reportID int64, err error) {
	err = tx.QueryRow(ctx,
		"INSERT INTO trust_report(client_id, client_info_ver, report_time, pcr_quote, verified) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		report.ClientID, clientInfoVer, time.Now().Format("2006/01/02 15:04:05"),
		report.PcrInfo.Quote.Quoted, report.Verified).Scan(&reportID)
	if err != nil {
		return -1, err
	}

	return reportID, nil
}

// insert report data into trust_report_manifest
func (psd *PostgreSqlDAO) saveReportManifest(tx pgx.Tx, ctx context.Context, report *entity.Report, reportID int64) (err error) {
	for _, mf := range report.Manifest {
		for index, item := range mf.Items {
			_, err = tx.Exec(context.Background(),
				"INSERT INTO trust_report_manifest(report_id, index, type, name, value, detail) VALUES ($1, $2, $3, $4, $5, $6)",
				reportID, index, mf.Type, item.Name, item.Value, item.Detail)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// insert report data into trust_report_pcr_info
func (psd *PostgreSqlDAO) saveReportPCRInfo(tx pgx.Tx, ctx context.Context, report *entity.Report, reportID int64) (err error) {
	for k, v := range report.PcrInfo.Values {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO trust_report_pcr_info(report_id, pcr_id, pcr_value) VALUES ($1, $2, $3)",
			reportID, k, v)
		if err != nil {
			return err
		}
	}

	return nil
}

// get report data from client_info table with clientInfoVer.
func (psd *PostgreSqlDAO) getClientInfo(ctx context.Context, clientInfo *entity.ClientInfo, clientID int64, clientInfoVer int) (err error) {
	ciRows, err := psd.conn.Query(ctx,
		"SELECT name, value FROM client_info WHERE client_id=$1 AND client_info_ver=$2",
		clientID, clientInfoVer)
	if err != nil {
		return err
	}
	defer ciRows.Close()

	for ciRows.Next() {
		var name string
		var value string
		err = ciRows.Scan(&name, &value)
		if err != nil {
			return err
		}
		clientInfo.Info[name] = value
	}

	return nil
}

// get report data from pcr_info table.
func (psd *PostgreSqlDAO) getPCRInfo(ctx context.Context, pcrInfo *entity.PcrInfo, reportID int64) (err error) {
	pcrRows, err := psd.conn.Query(context.Background(),
		"SELECT pcr_id, pcr_value FROM trust_report_pcr_info WHERE report_id=$1", reportID)
	if err != nil {
		return err
	}
	defer pcrRows.Close()

	pcrInfo.Values = map[int]string{}
	for pcrRows.Next() {
		var (
			id    int
			value string
		)
		err = pcrRows.Scan(&id, &value)
		if err != nil {
			return err
		}
		pcrInfo.Values[id] = value
	}

	return nil
}

// get report data from manifest table.
func (psd *PostgreSqlDAO) getManifest(ctx context.Context, manifests *[]entity.Manifest, reportID int64) (err error) {
	// select manifest
	mRows, err := psd.conn.Query(context.Background(),
		"SELECT type, name, value, detail FROM trust_report_manifest WHERE report_id=$1", reportID)
	if err != nil {
		return err
	}
	defer mRows.Close()

	for mRows.Next() {
		var (
			mType string
			mi    entity.ManifestItem
		)
		err = mRows.Scan(&mType, &mi.Name, &mi.Value, &mi.Detail)
		if err != nil {
			return err
		}
		// check if type existed
		isExisted := false
		for i, mf := range *manifests {
			if mf.Type == mType {
				isExisted = true
				(*manifests)[i].Items = append(mf.Items, mi)
				break
			}
		}
		if isExisted {
			continue
		}
		*manifests = append(*manifests, entity.Manifest{
			Type:  mType,
			Items: []entity.ManifestItem{mi},
		})
	}

	return nil
}

// SaveReport saves the trust report into database.
func (psd *PostgreSqlDAO) SaveReport(report *entity.Report) error {
	psd.Lock()
	defer psd.Unlock()

	var reportID int64
	var clientInfoVer int

	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}

	clientInfoVer, err = psd.updateClientInfo(tx, context.Background(), report)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	reportID, err = psd.saveReportContent(tx, context.Background(), report, clientInfoVer)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	err = psd.saveReportManifest(tx, context.Background(), report, reportID)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	err = psd.saveReportPCRInfo(tx, context.Background(), report, reportID)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	err = tx.Commit(context.Background())
	return err
}

// RegisterClient registers a new client and save its information.
func (psd *PostgreSqlDAO) RegisterClient(clientInfo *entity.ClientInfo, ic []byte, registered bool) (int64, error) {
	psd.Lock()
	defer psd.Unlock()

	var clientID int64
	var clientInfoVer int
	var deleted bool
	/* TODO: after completing register function, let this block of code effective
	if clientInfo == nil{
		return 0, errors.New("client info is empty")
	}
	if ic == ""{
		return 0, errors.New("ic is empty")
	}
	*/
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return 0, err
	}

	// check if client is registered or not
	err = tx.QueryRow(context.Background(),
		"SELECT id, client_info_ver, deleted FROM register_client WHERE ak_certificate = $1", ic).Scan(&clientID, &clientInfoVer, &deleted)
	if err == nil {
		if deleted {
			return 0, errors.New("client is deleted")
		}
		return 0, errors.New("client is registered")
	}

	// no client in register_client table, register a new one in it. set base_value_ver = 0
	clientInfoVer = 1
	deleted = !registered
	_, err = tx.Exec(context.Background(),
		"INSERT INTO register_client(client_info_ver, register_time, ak_certificate, online, deleted, base_value_ver) VALUES ($1, $2, $3, $4, $5, $6)",
		clientInfoVer, time.Now(), ic, true, deleted, 0)
	if err != nil {
		tx.Rollback(context.Background())
		return 0, err
	}
	err = tx.QueryRow(context.Background(),
		"SELECT id FROM register_client WHERE ak_certificate = $1", ic).Scan(&clientID)
	if err != nil {
		tx.Rollback(context.Background())
		return 0, err
	}

	// write the client related information into client_info table
	err = psd.saveClientInfo(tx, context.Background(), clientInfo, clientID, clientInfoVer)
	if err != nil {
		tx.Rollback(context.Background())
		return 0, err
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return 0, err
	}
	return clientID, nil
}

// UnRegisterClient set only deleted flag in register_client table, but reserves all other client information.
func (psd *PostgreSqlDAO) UnRegisterClient(clientID int64) error {
	psd.Lock()
	defer psd.Unlock()

	_, err := psd.conn.Exec(context.Background(),
		"UPDATE register_client SET deleted=$1, online=$2 WHERE id=$3", true, false, clientID)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) SaveBaseValue(clientID int64, meaInfo *entity.MeasurementInfo) error {
	psd.Lock()
	defer psd.Unlock()

	var baseValueVer int
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}
	err = tx.QueryRow(context.Background(),
		"SELECT base_value_ver FROM register_client WHERE id = $1", clientID).Scan(&baseValueVer)
	// if baseValue is empty or baseValue == 0, initialize base_value_ver.
	if err != nil || baseValueVer == 0 {
		baseValueVer = 1
	} else {
		baseValueVer++
	}

	_, err = tx.Exec(context.Background(),
		"UPDATE register_client SET base_value_ver = $1 WHERE id = $2",
		baseValueVer, clientID)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	for k, v := range meaInfo.PcrInfo.Values {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO base_value_pcr_info(client_id, base_value_ver, pcr_id, pcr_value) VALUES ($1, $2, $3, $4)",
			clientID, baseValueVer, k, v)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}
	}

	for _, mf := range meaInfo.Manifest {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO base_value_manifest(client_id, base_value_ver, type, name, value) "+
				"VALUES ($1, $2, $3, $4, $5)",
			clientID, baseValueVer, mf.Type, mf.Name, mf.Value)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}

	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}
	return nil
}

// SelectAllClientIds finds all registered clients and returns their ids.
func (psd *PostgreSqlDAO) SelectAllRegisteredClientIds() ([]int64, error) {
	psd.Lock()
	defer psd.Unlock()

	var clientIds []int64
	rows, err := psd.conn.Query(context.Background(), "SELECT id FROM register_client WHERE deleted=false")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ci int64
		err = rows.Scan(&ci)
		if err != nil {
			return nil, err
		}
		clientIds = append(clientIds, ci)
	}
	return clientIds, nil
}

func (psd *PostgreSqlDAO) SelectAllClientIds() ([]int64, error) {
	psd.Lock()
	defer psd.Unlock()

	var clientIds []int64
	rows, err := psd.conn.Query(context.Background(), "SELECT id FROM register_client")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ci int64
		err = rows.Scan(&ci)
		if err != nil {
			return nil, err
		}
		clientIds = append(clientIds, ci)
	}
	return clientIds, nil
}

// SelectReportById find report by client id
func (psd *PostgreSqlDAO) SelectReportsById(clientId int64) ([]*entity.Report, error) {
	psd.Lock()
	defer psd.Unlock()

	var reports []*entity.Report

	rRows, err := psd.conn.Query(context.Background(),
		"SELECT id, client_info_ver, report_time, pcr_quote, verified FROM trust_report WHERE client_id=$1", clientId)
	if err != nil {
		return nil, err
	}

	for rRows.Next() {
		r := entity.Report{ClientID: clientId, ClientInfo: entity.ClientInfo{Info: map[string]string{}}}
		err = rRows.Scan(&r.ReportId, &r.ClientInfoVer, &r.ReportTime, &r.PcrInfo.Quote.Quoted, &r.Verified)
		if err != nil {
			rRows.Close()
			return nil, err
		}
		reports = append(reports, &r)
	}
	rRows.Close()

	for _, r := range reports {
		err = psd.getClientInfo(context.Background(), &r.ClientInfo, r.ClientID, r.ClientInfoVer)
		if err != nil {
			return nil, err
		}

		err = psd.getPCRInfo(context.Background(), &r.PcrInfo, r.ReportId)
		if err != nil {
			return nil, err
		}

		err = psd.getManifest(context.Background(), &r.Manifest, r.ReportId)
		if err != nil {
			return nil, err
		}
	}

	return reports, nil
}

func (psd *PostgreSqlDAO) SelectLatestReportById(clientId int64) (*entity.Report, error) {
	psd.Lock()
	defer psd.Unlock()

	r := entity.Report{ClientID: clientId, ClientInfo: entity.ClientInfo{Info: map[string]string{}}}
	err := psd.conn.QueryRow(context.Background(),
		"SELECT id, client_info_ver, report_time, pcr_quote, verified FROM trust_report WHERE client_id=$1 ORDER BY report_time DESC LIMIT 1", clientId).
		Scan(&r.ReportId, &r.ClientInfoVer, &r.ReportTime, &r.PcrInfo.Quote.Quoted, &r.Verified)
	if err != nil {
		return nil, err
	}
	err = psd.getClientInfo(context.Background(), &r.ClientInfo, r.ClientID, r.ClientInfoVer)
	if err != nil {
		return nil, err
	}

	err = psd.getPCRInfo(context.Background(), &r.PcrInfo, r.ReportId)
	if err != nil {
		return nil, err
	}

	err = psd.getManifest(context.Background(), &r.Manifest, r.ReportId)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (psd *PostgreSqlDAO) SelectBaseValueById(clientId int64) (*entity.MeasurementInfo, error) {
	psd.Lock()
	defer psd.Unlock()

	var (
		baseValueVer int
		meas         []entity.Measurement
	)
	err := psd.conn.QueryRow(context.Background(),
		"SELECT base_value_ver FROM register_client WHERE id=$1", clientId).Scan(&baseValueVer)
	if err != nil {
		return nil, err
	}

	pi := entity.PcrInfo{
		Values: map[int]string{},
	}
	pcrRows, err := psd.conn.Query(context.Background(),
		"SELECT pcr_id, pcr_value FROM base_value_pcr_info WHERE client_id=$1 AND base_value_ver=$2", clientId, baseValueVer)
	if err != nil {
		return nil, err
	}
	for pcrRows.Next() {
		var (
			id    int
			value string
		)
		err = pcrRows.Scan(&id, &value)
		if err != nil {
			pcrRows.Close()
			return nil, err
		}
		pi.Values[id] = value
	}
	pcrRows.Close()

	mRows, err := psd.conn.Query(context.Background(),
		"SELECT type, name, value FROM base_value_manifest WHERE client_id=$1 AND base_value_ver=$2", clientId, baseValueVer)
	if err != nil {
		return nil, err
	}

	for mRows.Next() {
		var (
			mType string
			name  string
			value string
		)
		err = mRows.Scan(&mType, &name, &value)
		if err != nil {
			mRows.Close()
			return nil, err
		}
		meas = append(meas, entity.Measurement{
			Type:  mType,
			Name:  name,
			Value: value,
		})
	}
	mRows.Close()

	result := &entity.MeasurementInfo{
		ClientID: clientId,
		PcrInfo:  pi,
		Manifest: meas,
	}
	return result, nil
}

func (psd *PostgreSqlDAO) SelectClientById(clientId int64) (*entity.RegisterClient, error) {
	psd.Lock()
	defer psd.Unlock()

	result := entity.RegisterClient{}

	err := psd.conn.QueryRow(context.Background(),
		"SELECT * FROM register_client WHERE id=$1", clientId).Scan(&result.ClientID, &result.ClientInfoVer, &result.RegisterTime,
		&result.AkCertificate, &result.IsOnline, &result.IsDeleted, &result.BaseValueVer)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// CreatePostgreSQLDAO creates a postgre database connection to read and store data.
func CreatePostgreSQLDAO() (DAO, error) {
	cfg := config.GetDefault(config.ConfServer)
	host := cfg.GetHost()
	port := cfg.GetDBPort()
	dbname := cfg.GetDBName()
	user := cfg.GetUser()
	password := cfg.GetPassword()
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, password, host, port, dbname)
	c, err := pgx.Connect(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &PostgreSqlDAO{conn: c}, nil
}

// Destroy closes the database connection.
func (psd *PostgreSqlDAO) Destroy() {
	psd.Lock()
	defer psd.Unlock()

	psd.conn.Close(context.Background())
}

func (psd *PostgreSqlDAO) SelectAllClientInfobyId(clientId int64) (map[string]string, error) {
	psd.Lock()
	defer psd.Unlock()
	result := entity.ClientInfo{Info: map[string]string{}}
	var clientInfoVer int
	err := psd.conn.QueryRow(context.Background(),
		sqlSelectClientInfoVerById, clientId).
		Scan(&clientInfoVer)
	if err != nil {
		return nil, err
	}
	err = psd.getClientInfo(context.Background(), &result, clientId, clientInfoVer)
	if err != nil {
		return nil, err
	}
	return result.Info, nil
}

func (psd *PostgreSqlDAO) SelectClientInfobyId(clientId int64, infoNames []string) (map[string]string, error) {
	psd.Lock()
	defer psd.Unlock()
	var clientInfoVer int
	err := psd.conn.QueryRow(context.Background(),
		sqlSelectClientInfoVerById, clientId).
		Scan(&clientInfoVer)
	if err != nil {
		return nil, err
	}
	result := map[string]string{}
	for _, in := range infoNames {
		var infoValue string
		err := psd.conn.QueryRow(context.Background(),
			"SELECT value FROM client_info WHERE client_id=$1 AND client_info_ver=$2 AND name=$3",
			clientId, clientInfoVer, in).Scan(&infoValue)
		if err != nil {
			return nil, err
		}
		result[in] = infoValue
	}
	return result, nil
}

func (psd *PostgreSqlDAO) UpdateRegisterStatusById(clientId int64, isDeleted bool) error {
	psd.Lock()
	defer psd.Unlock()
	_, err := psd.conn.Exec(context.Background(),
		"UPDATE register_client SET deleted=$1 WHERE id=$2", isDeleted, clientId)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) UpdateRegisterClient(rc *entity.RegisterClient) error {
	psd.Lock()
	defer psd.Unlock()
	_, err := psd.conn.Exec(context.Background(),
		"UPDATE register_client SET register_time=$1, ak_certificate=$2, online=$3, deleted=$4 WHERE id=$5",
		 rc.RegisterTime, rc.AkCertificate, rc.IsOnline, rc.IsDeleted, rc.ClientID)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) SelectContainerByUUId(uuID string) (*entity.Container, error) {
	psd.Lock()
	defer psd.Unlock()

	result := entity.Container{}

	err := psd.conn.QueryRow(context.Background(),
		"SELECT * FROM container WHERE uuid=$1", uuID).Scan(&result.UUID, &result.ClientId, &result.BaseValueVer,
		&result.Online, &result.Deleted)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (psd *PostgreSqlDAO) SelectContainerBaseValueByUUId(uuID string) (*entity.ContainerBaseValue, error) {
	psd.Lock()
	defer psd.Unlock()
	result := entity.ContainerBaseValue{Value: map[string]string{}}
	var (
		baseValueVer int
	)
	err := psd.conn.QueryRow(context.Background(),
		"SELECT base_value_ver FROM container WHERE uuid=$1", uuID).Scan(&baseValueVer)
	if err != nil {
		return nil, err
	}

	mRows, err := psd.conn.Query(context.Background(),
		"SELECT name, value FROM container_base_value WHERE container_uuid=$1 AND base_value_ver=$2", uuID, baseValueVer)
	if err != nil {
		return nil, err
	}
	defer mRows.Close()
	for mRows.Next() {
		var (
			name  string
			value string
		)
		err = mRows.Scan(&name, &value)
		if err != nil {
			return nil, err
		}
		result.Value[name] = value
	}
	result.ContainerUUID = uuID
	return &result, nil
}

func (psd *PostgreSqlDAO) InsertContainer(c *entity.Container) error {
	psd.Lock()
	defer psd.Unlock()

	var deleted bool
	// check if container is existed
	err := psd.conn.QueryRow(context.Background(),
		"SELECT deleted FROM container WHERE uuid = $1", c.UUID).Scan(&deleted)
	if err == nil {
		if deleted {
			return errors.New("container is deleted")
		}
		return errors.New("container is existed")
	}

	_, err = psd.conn.Exec(context.Background(),
		"INSERT INTO container(uuid, client_id, base_value_ver, online, deleted) VALUES ($1, $2, $3, $4, $5)",
		c.UUID, c.ClientId, 0, c.Online, c.Deleted)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) InsertContainerBaseValue(cbv *entity.ContainerBaseValue) error {
	psd.Lock()
	defer psd.Unlock()

	var baseValueVer int
	err := psd.conn.QueryRow(context.Background(),
		"SELECT base_value_ver FROM container WHERE uuid = $1", cbv.ContainerUUID).Scan(&baseValueVer)
	// if baseValue is empty or baseValue == 0, initialize base_value_ver.
	if err != nil || baseValueVer == 0 {
		baseValueVer = 1
	} else {
		baseValueVer++
	}

	_, err = psd.conn.Exec(context.Background(),
		"UPDATE container SET base_value_ver = $1 WHERE uuid = $2",
		baseValueVer, cbv.ContainerUUID)
	if err != nil {
		return err
	}

	for k, v := range cbv.Value {
		_, err = psd.conn.Exec(context.Background(),
			"INSERT INTO container_base_value(container_uuid, base_value_ver, name, value) VALUES ($1, $2, $3, $4)",
			cbv.ContainerUUID, baseValueVer, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (psd *PostgreSqlDAO) UpdateContainerRegistryStatusByUUId(uuID string, isDeleted bool) error {
	psd.Lock()
	defer psd.Unlock()
	_, err := psd.conn.Exec(context.Background(),
		"UPDATE container SET deleted=$1 WHERE uuid=$2", isDeleted, uuID)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) SelectAllContainerUUIds() ([]string, error) {
	psd.Lock()
	defer psd.Unlock()

	var uuids []string
	rows, err := psd.conn.Query(context.Background(), "SELECT uuid FROM container")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uuid string
		err = rows.Scan(&uuid)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, uuid)
	}
	return uuids, nil
}
func (psd *PostgreSqlDAO) SelectDeviceById(deviceId int64) (*entity.PcieDevice, error) {
	psd.Lock()
	defer psd.Unlock()

	result := entity.PcieDevice{}

	err := psd.conn.QueryRow(context.Background(),
		"SELECT * FROM device WHERE id=$1", deviceId).Scan(&result.ID, &result.ClientId, &result.BaseValueVer,
		&result.Online, &result.Deleted)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (psd *PostgreSqlDAO) SelectDeviceBaseValueById(deviceId int64) (*entity.PcieBaseValue, error) {
	psd.Lock()
	defer psd.Unlock()
	result := entity.PcieBaseValue{Value: map[string]string{}}
	var (
		baseValueVer int
	)
	err := psd.conn.QueryRow(context.Background(),
		"SELECT base_value_ver FROM device WHERE id=$1", deviceId).Scan(&baseValueVer)
	if err != nil {
		return nil, err
	}

	mRows, err := psd.conn.Query(context.Background(),
		"SELECT name, value FROM device_base_value WHERE device_id=$1 AND base_value_ver=$2", deviceId, baseValueVer)
	if err != nil {
		return nil, err
	}
	defer mRows.Close()
	for mRows.Next() {
		var (
			name  string
			value string
		)
		err = mRows.Scan(&name, &value)
		if err != nil {
			return nil, err
		}
		result.Value[name] = value
	}
	result.DeviceID = deviceId
	return &result, nil
}

func (psd *PostgreSqlDAO) InsertDevice(c *entity.PcieDevice) error {
	psd.Lock()
	defer psd.Unlock()

	var deleted bool
	// check if device is existed
	err := psd.conn.QueryRow(context.Background(),
		"SELECT deleted FROM device WHERE id = $1", c.ID).Scan(&deleted)
	if err == nil {
		if deleted {
			return errors.New("device is deleted")
		}
		return errors.New("device is existed")
	}

	_, err = psd.conn.Exec(context.Background(),
		"INSERT INTO device(id, client_id, base_value_ver, online, deleted) VALUES ($1, $2, $3, $4, $5)",
		c.ID, c.ClientId, 0, c.Online, c.Deleted)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) InsertDeviceBaseValue(pbv *entity.PcieBaseValue) error {
	psd.Lock()
	defer psd.Unlock()

	var baseValueVer int
	err := psd.conn.QueryRow(context.Background(),
		"SELECT base_value_ver FROM device WHERE id = $1", pbv.DeviceID).Scan(&baseValueVer)
	// if baseValue is empty or baseValue == 0, initialize base_value_ver.
	if err != nil || baseValueVer == 0 {
		baseValueVer = 1
	} else {
		baseValueVer++
	}

	_, err = psd.conn.Exec(context.Background(),
		"UPDATE device SET base_value_ver = $1 WHERE id = $2",
		baseValueVer, pbv.DeviceID)
	if err != nil {
		return err
	}

	for k, v := range pbv.Value {
		_, err = psd.conn.Exec(context.Background(),
			"INSERT INTO device_base_value(device_id, base_value_ver, name, value) VALUES ($1, $2, $3, $4)",
			pbv.DeviceID, baseValueVer, k, v)
		if err != nil {
			return err
		}
	}
	return nil
}

func (psd *PostgreSqlDAO) UpdateDeviceRegistryStatusById(deviceId int64, isDeleted bool) error {
	psd.Lock()
	defer psd.Unlock()
	_, err := psd.conn.Exec(context.Background(),
		"UPDATE device SET deleted=$1 WHERE id=$2", isDeleted, deviceId)
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) SelectAllDeviceIds() ([]int64, error) {
	psd.Lock()
	defer psd.Unlock()

	var deviceIds []int64
	rows, err := psd.conn.Query(context.Background(), "SELECT id FROM device")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var di int64
		err = rows.Scan(&di)
		if err != nil {
			return nil, err
		}
		deviceIds = append(deviceIds, di)
	}
	return deviceIds, nil
}
