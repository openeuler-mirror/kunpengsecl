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
		string(report.PcrInfo.Quote), report.Verified).Scan(&reportID)
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
	for _, pv := range report.PcrInfo.Values {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO trust_report_pcr_info(report_id, pcr_id, alg_name, pcr_value) VALUES ($1, $2, $3, $4)",
			reportID, pv.Id, report.PcrInfo.AlgName, pv.Value)
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
func (psd *PostgreSqlDAO) RegisterClient(clientInfo *entity.ClientInfo, ic string) (int64, error) {
	var clientID int64
	var clientInfoVer int
	var deleted bool

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
