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

	tx.Commit(context.Background())

	return nil
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
