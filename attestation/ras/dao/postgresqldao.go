package dao

import (
	"context"
	"errors"
	"fmt"
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
	conn *pgx.Conn
}

// SaveReport saves the trust report into database.
func (psd *PostgreSqlDAO) SaveReport(report *entity.Report) error {
	var reportID int64
	var clientInfoVer int

	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}

	// If there are name-value pairs in the clientinfo map, save them with a new clientInfoVer.
	if len(report.ClientInfo.Info) > 0 {
		err = tx.QueryRow(context.Background(),
			"SELECT client_info_ver FROM register_client WHERE id=$1", report.ClientID).Scan(&clientInfoVer)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}
		clientInfoVer++
		_, err = tx.Exec(context.Background(),
			"UPDATE register_client SET client_info_ver=$1 WHERE id=$2", clientInfoVer, report.ClientID)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}
		for name, value := range report.ClientInfo.Info {
			_, err = tx.Exec(context.Background(),
				"INSERT INTO client_info(client_id, client_info_ver, name, value) VALUES ($1, $2, $3, $4)",
				report.ClientID, clientInfoVer, name, value)
			if err != nil {
				tx.Rollback(context.Background())
				return err
			}
		}
	}

	// insert report data into trust_report table and return reportID
	err = tx.QueryRow(context.Background(),
		"INSERT INTO trust_report(client_id, client_info_ver, report_time, pcr_quote, verified) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		report.ClientID, clientInfoVer, time.Now().Format("2006/01/02 15:04:05"),
		string(report.PcrInfo.Quote.Quoted), report.Verified).Scan(&reportID)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	// insert report data into trust_report_manifest
	for _, mf := range report.Manifest {
		for index, item := range mf.Items {
			_, err = tx.Exec(context.Background(),
				"INSERT INTO trust_report_manifest(report_id, index, type, name, value, detail) VALUES ($1, $2, $3, $4, $5, $6)",
				reportID, index, mf.Type, item.Name, item.Value, item.Detail)
			if err != nil {
				tx.Rollback(context.Background())
				return err
			}
		}
	}

	// insert report data into trust_report_pcr_info
	for k, v := range report.PcrInfo.Values {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO trust_report_pcr_info(report_id, pcr_id, alg_name, pcr_value) VALUES ($1, $2, $3, $4)",
			reportID, k, report.PcrInfo.AlgName, v)
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

// RegisterClient registers a new client and save its information.
func (psd *PostgreSqlDAO) RegisterClient(clientInfo *entity.ClientInfo, ic []byte) (int64, error) {
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
	if err != nil {
		// no client in register_client table, register a new one in it.
		clientInfoVer = 1
		deleted = false
		_, err = tx.Exec(context.Background(),
			"INSERT INTO register_client(client_info_ver, register_time, ak_certificate, online, deleted) VALUES ($1, $2, $3, $4, $5)",
			clientInfoVer, time.Now(), ic, true, deleted)
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
	} else {
		return 0, err
	}

	if deleted {
		return 0, errors.New("client is deleted")
	}

	// write the client related information into client_info table
	for name, value := range clientInfo.Info {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO client_info(client_id, client_info_ver, name, value) VALUES ($1, $2, $3, $4)",
			clientID, clientInfoVer, name, value)
		if err != nil {
			tx.Rollback(context.Background())
			return 0, err
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return 0, err
	}
	return clientID, nil
}

// UnRegisterClient set only deleted flag in register_client table, but reserves all other client information.
func (psd *PostgreSqlDAO) UnRegisterClient(clientID int64) error {
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}
	_, err = tx.Exec(context.Background(),
		"UPDATE register_client SET deleted=$1, online=$2 WHERE id=$3", true, false, clientID)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}
	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}
	return nil
}

func (psd *PostgreSqlDAO) SaveBaseValue(clientID int64, info entity.PcrInfo, manifest []entity.Manifest) error {
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

	for k, v := range info.Values {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO base_value_pcr_info(client_id, base_value_ver, pcr_id, alg_name, pcr_value) VALUES ($1, $2, $3, $4, $5)",
			clientID, baseValueVer, k, info.AlgName, v)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}
	}

	for _, mf := range manifest {
		for _, item := range mf.Items {
			_, err = tx.Exec(context.Background(),
				"INSERT INTO base_value_manifest(client_id, base_value_ver, type, name, value, detail) "+
					"VALUES ($1, $2, $3, $4, $5, $6)",
				clientID, baseValueVer, mf.Type, item.Name, item.Value, item.Detail)
			if err != nil {
				tx.Rollback(context.Background())
				return err
			}
		}
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return err
	}
	return nil
}

// SelectAllClientIds finds all registered clients and returns their ids.
func (psd *PostgreSqlDAO) SelectAllClientIds() ([]int64, error) {
	var clientIds []int64
	rows, err := psd.conn.Query(context.Background(), "SELECT id FROM register_client")
	if err != nil {
		return nil, err
	}
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
	var reports []*entity.Report

	rRows, err := psd.conn.Query(context.Background(),
		"SELECT id, client_info_ver, report_time, pcr_quote, verified FROM trust_report WHERE client_id=$1", clientId)
	if err != nil {
		return nil, err
	}
	for rRows.Next() {
		var (
			report        entity.Report
			reportId      int64
			clientInfoVer int
			reportTime    time.Time
			pcrQuote      []byte
			verified      bool
			clientInfo    entity.ClientInfo
			pcrInfo       entity.PcrInfo
			manifests     []entity.Manifest
		)
		clientInfo.Info = map[string]string{}
		err = rRows.Scan(&reportId, &clientInfoVer, &reportTime, &pcrQuote, &verified)
		if err != nil {
			return nil, err
		}
		rRows.Close()

		// Select client info
		ciRows, err := psd.conn.Query(context.Background(),
			"SELECT name, value FROM client_info WHERE client_id=$1 AND client_info_ver=$2",
			clientId, clientInfoVer)
		if err != nil {
			return nil, err
		}
		for ciRows.Next() {
			var name string
			var value string
			err = ciRows.Scan(&name, &value)
			if err != nil {
				return nil, err
			}
			clientInfo.Info[name] = value
		}
		ciRows.Close()

		//Select pcr info
		pcrRows, err := psd.conn.Query(context.Background(),
			"SELECT pcr_id, alg_name, pcr_value FROM trust_report_pcr_info WHERE report_id=$1", reportId)
		if err != nil {
			return nil, err
		}
		pcrInfo = entity.PcrInfo{
			Values: map[int]string{},
			Quote: entity.PcrQuote{
				Quoted: pcrQuote,
			},
		}
		for pcrRows.Next() {
			var (
				id      int
				algName string
				value   string
			)
			err = pcrRows.Scan(&id, &algName, &value)
			if err != nil {
				return nil, err
			}
			pcrInfo.AlgName = algName
			pcrInfo.Values[id] = value
		}
		pcrRows.Close()

		// select manifest
		mRows, err := psd.conn.Query(context.Background(),
			"SELECT type, name, value, detail FROM trust_report_manifest WHERE report_id=$1", reportId)
		if err != nil {
			return nil, err
		}
		for mRows.Next() {
			var (
				mType  string
				name   string
				value  string
				detail string
			)
			err = mRows.Scan(&mType, &name, &value, &detail)
			if err != nil {
				return nil, err
			}
			// check if type existed
			isExisted := false
			for i, mf := range manifests {
				if mf.Type == mType {
					isExisted = true
					manifests[i].Items = append(mf.Items, entity.ManifestItem{
						Name:   name,
						Value:  value,
						Detail: detail,
					})
					break
				}
			}
			if !isExisted {
				manifests = append(manifests, entity.Manifest{
					Type: mType,
					Items: []entity.ManifestItem{
						{
							Name:   name,
							Value:  value,
							Detail: detail,
						},
					},
				})
			}
		}
		mRows.Close()

		report = entity.Report{
			PcrInfo:       pcrInfo,
			Manifest:      manifests,
			ClientID:      clientId,
			ClientInfo:    clientInfo,
			Verified:      verified,
			ReportId:      reportId,
			ClientInfoVer: clientInfoVer,
			ReportTime:    reportTime,
		}
		reports = append(reports, &report)
	}
	return reports, nil
}

func (psd *PostgreSqlDAO) SelectLatestReportById(clientId int64) (*entity.Report, error) {
	reports, err := psd.SelectReportsById(clientId)
	if err != nil {
		return nil, err
	}
	if reports == nil {
		return nil, fmt.Errorf("report of client %v doesn't exist", clientId)
	}
	result := reports[0]
	for _, r := range reports {
		if r.ReportTime.After(result.ReportTime) {
			result = r
		}
	}
	return result, nil
}

func (psd *PostgreSqlDAO) SelectBaseValueById(clientId int64) (*entity.MeasurementInfo, error) {
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
		"SELECT pcr_id, alg_name, pcr_value FROM base_value_pcr_info WHERE client_id=$1 AND base_value_ver=$2", clientId, baseValueVer)
	if err != nil {
		return nil, err
	}
	for pcrRows.Next() {
		var (
			id      int
			algName string
			value   string
		)
		err = pcrRows.Scan(&id, &algName, &value)
		if err != nil {
			return nil, err
		}
		pi.AlgName = algName
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

// CreatePostgreSQLDAO creates a postgre database connection to read and store data.
func CreatePostgreSQLDAO() (*PostgreSqlDAO, error) {
	host := config.GetDefault().GetHost()
	port := config.GetDefault().GetPort()
	dbname := config.GetDefault().GetDBName()
	user := config.GetDefault().GetUser()
	password := config.GetDefault().GetPassword()
	url := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", user, password, host, port, dbname)
	c, err := pgx.Connect(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &PostgreSqlDAO{conn: c}, nil
}

// Destroy closes the database connection.
func (psd *PostgreSqlDAO) Destroy() {
	psd.conn.Close(context.Background())
}
