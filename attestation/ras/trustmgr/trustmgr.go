package trustmgr

/*
	trustmgr is used to register, save reports, extract base value, provide the newest report, etc.
*/
import (
	"errors"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/dao"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

type TrustMgr struct {
}

var validator Validator
var extractor Extractor
var postgreSqlDAO *dao.PostgreSqlDAO

// Validator will be implemented to validate integrity of report
type Validator interface {
	Validate(report *entity.Report) error
}

// Extractor will be implemented to extract base value from report
type Extractor interface {
	Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error
}

// SetValidator is used to register variety validator
func SetValidator(v Validator) {
	validator = v
}

// SetExtractor is used to register variety extractor
func SetExtractor(e Extractor) {
	extractor = e
}

// RecordReport will be called by clientapi to validate and save trust report
func RecordReport(report *entity.Report) error {
	if validator == nil {
		return errors.New("validator is nil")
	} else {
		err := validator.Validate(report)
		if err != nil {
			report.Verified = false
		} else {
			report.Verified = true
		}
		psd, err := getPostgreSQLDAO()
		if err != nil {
			return err
		}
		err = psd.SaveReport(report)
		if err != nil {
			return err
		}
		// if this is the first report of this RAC, extract base value
		isFirstReport, err := isFirstReport(report.ClientID)
		if err != nil {
			return err
		}
		baseValue := entity.MeasurementInfo{}
		if isFirstReport {
			extractor.Extract(report, &baseValue)
		}
		psd.SaveBaseValue(report.ClientID, &baseValue)

		return nil
	}
}

func RegisterClient(clientInfo *entity.ClientInfo, ic []byte) (int64, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return 0, err
	}
	clientId, err := psd.RegisterClient(clientInfo, ic)
	if err != nil {
		return 0, err
	}
	return clientId, nil
}

func UnRegisterClient(clientId int64) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	err = psd.UnRegisterClient(clientId)
	if err != nil {
		return err
	}
	return nil
}

func GetLatestReportById(clientId int64) (*entity.Report, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectLatestReportById(clientId)
}

func getPostgreSQLDAO() (*dao.PostgreSqlDAO, error) {
	var err error
	if postgreSqlDAO == nil {
		postgreSqlDAO, err = dao.CreatePostgreSQLDAO()
		if err != nil {
			return nil, err
		}
	}
	return postgreSqlDAO, nil
}

func isFirstReport(clientId int64) (bool, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return false, err
	}
	reports, err := psd.SelectReportsById(clientId)
	if err != nil {
		return false, err
	}
	if reports == nil {
		return true, nil
	}
	return false, nil
}
