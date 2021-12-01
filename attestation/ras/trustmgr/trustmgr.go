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
var dbDAO dao.DAO

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

func getPostgreSQLDAO() (dao.DAO, error) {
	var err error
	if dbDAO == nil {
		dbDAO, err = dao.CreatePostgreSQLDAO()
		if err != nil {
			return nil, err
		}
	}
	return dbDAO, nil
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

func GetAllRegisteredClientID() ([]int64, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectAllRegisteredClientIds()
}

func GetAllClientID() ([]int64, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectAllClientIds()
}

func GetBaseValueById(clientId int64) (*entity.MeasurementInfo, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectBaseValueById(clientId)
}

func GetRegisterClientById(clientId int64) (*entity.RegisterClient, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectClientById(clientId)
}

func SaveBaseValueById(clientId int64, meaInfo *entity.MeasurementInfo) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.SaveBaseValue(clientId, meaInfo)
}

//return the name & type & time stamp of the id

func GetInfoByID(clientId int64, infoNames []string) (map[string]string, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return map[string]string{}, err
	}
	return psd.SelectInfobyId(clientId, infoNames)
}
