package dao

import (
	"context"
	"fmt"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"github.com/jackc/pgx/v4"
	"github.com/spf13/viper"
	"os"
	"time"
)

/*
	PostgreSqlDAO implements dao.
	conn is a connection initialized in CreatePostgreSqlDAO() and destroyed in Destroy()
 */
type PostgreSqlDAO struct {
	conn *pgx.Conn
}
/*
	SaveReport use conn to execute a transaction for insert data into tables
 */
func (psd *PostgreSqlDAO) SaveReport(report *entity.Report) error {
	var reportId int64
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}

	// insert report data into trust_report, use RETURNING to get report_id
	err = tx.QueryRow(context.Background(),
		"INSERT INTO trust_report(client_id, report_time, pcr_quote) VALUES ($1, $2, $3) RETURNING report_id",
		report.ClientId,
		time.Now().Format("2006/01/02 15:04:05"),
		string(report.PcrInfo.Quote)).Scan(&reportId)

	if err != nil {
		tx.Rollback(context.Background())
		return err
	}

	// insert report data into client_info
	ci := report.ClientInfo.Info
	for name, value := range ci {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO client_info(report_id, name, value) VALUES ($1, $2, $3)",
			reportId,
			name,
			value)
		if err != nil {
			tx.Rollback(context.Background())
			return err
		}
	}

	// insert report data into trust_report_manifest
	manifests := report.Manifest
	for _, mf := range manifests {
		mfType := mf.Type
		mfItems := mf.Items
		for index, item := range mfItems {
			_, err = tx.Exec(context.Background(),
				"INSERT INTO trust_report_manifest(report_id, type, index, name, value, detail) VALUES ($1, $2, $3, $4, $5, $6)",
				reportId,
				mfType,
				index,
				item.Name,
				item.Value,
				item.Detail)
			if err != nil {
				tx.Rollback(context.Background())
				return err
			}
		}
	}

	// insert report data into trust_report_pcr_info
	pcrValues := report.PcrInfo.Values
	for _, pv := range pcrValues {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO trust_report_pcr_info(report_id, algorithm, pcr_id, pcr_value) VALUES ($1, $2, $3, $4)",
			reportId,
			report.PcrInfo.Algorithm,
			pv.Id,
			pv.Value)
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

/*
	RegisterClient start a transaction, first insert clientInfo into table client_info,
	get the client_info_id and then insert data into table register_client.
 */
func (psd *PostgreSqlDAO) RegisterClient(clientInfo *entity.ClientInfo, ic string) (int64, error) {
	var clientInfoId int64
	var clientId int64
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return 0, err
	}

	/*
		Insert report data into client_info.
		Using serial to generate client_info_id is impossible because clientInfo is a map,
		several rows have the same client_info_id.
		Here we use table client_info_id to record client_info_id value.
	 */
	err = tx.QueryRow(context.Background(),
		"INSERT INTO client_info_id(online) VALUES ($1) RETURNING id", true).Scan(&clientInfoId)
	if err != nil {
		tx.Rollback(context.Background())
		return 0, err
	}
	for name, value := range clientInfo.Info {
		_, err = tx.Exec(context.Background(),
			"INSERT INTO client_info(client_info_id, name, value) VALUES ($1, $2, $3)",
			clientInfoId,
			name,
			value)
		if err != nil {
			tx.Rollback(context.Background())
			return 0, err
		}
	}

	// Insert data into register_client
	err = tx.QueryRow(context.Background(),
		"INSERT INTO register_client(client_info_id, register_time, ak_certificate) " +
		"VALUES ($1, $2, $3) RETURNING client_id", clientInfoId, time.Now(), ic).Scan(&clientId)
	if err != nil {
		tx.Rollback(context.Background())
		return 0, err
	}
	err = tx.Commit(context.Background())
	if err != nil {
		return 0, err
	}
	return clientId, nil
}

/*
	UnRegisterClient delete client data from table client_info, client_info_id and register_client.
 */
func (psd *PostgreSqlDAO) UnRegisterClient(clientId int64) error {
	var clientInfoId int64
	tx, err := psd.conn.Begin(context.Background())
	if err != nil {
		return err
	}
	err = tx.QueryRow(context.Background(),
		"SELECT client_info_id FROM register_client WHERE client_id = $1",
		clientId).Scan(&clientInfoId)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}
	_, err = tx.Exec(context.Background(), "DELETE FROM client_info WHERE client_info_id = $1", clientInfoId)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}
	_, err = tx.Exec(context.Background(), "DELETE FROM client_info_id WHERE id = $1", clientInfoId)
	if err != nil {
		tx.Rollback(context.Background())
		return err
	}
	_, err = tx.Exec(context.Background(), "DELETE FROM register_client WHERE client_id = $1", clientId)
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

func (psd *PostgreSqlDAO) SelectAllClientIds() ([]int64, error){
	var clientIds []int64
	rows, err := psd.conn.Query(context.Background(),
		"SELECT client_id FROM register_client")
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

func (psd *PostgreSqlDAO) init() error {
	// use viper to read config for connecting database
	path, err:= os.Getwd()
	if err != nil {
		return err
	}
	path = path + "\\..\\config"
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(path)
	err = viper.ReadInConfig()
	if err != nil {
		fmt.Println("读取配置文件失败")
		return err
	}
	host := viper.GetString("database.host")
	port := viper.GetString("database.port")
	dbname := viper.GetString("database.dbname")
	user := viper.GetString("database.user")
	password := viper.GetString("database.password")
	url := "postgres://"+user+":"+password+"@"+host+":"+port+"/"+dbname
	psd.conn, err = pgx.Connect(context.Background(), url)
	if err != nil {
		fmt.Println("数据库连接失败")
		return err
	}
	return nil
}

/*
	use factory mode to get a pointer of PostgreSqlDAO
 */
func CreatePostgreSqlDAO() *PostgreSqlDAO {
	psd := new(PostgreSqlDAO)
	psd.init()
	return psd
}

func (psd *PostgreSqlDAO) Destroy() {
	psd.conn.Close(context.Background())
}
