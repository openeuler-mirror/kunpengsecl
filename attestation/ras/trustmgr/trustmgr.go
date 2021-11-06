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
			return err
		}
		psd, err := getPostgreSQLDAO()
		if err != nil {
			return err
		}
		defer psd.Destroy()
		err = psd.SaveReport(report)
		if err != nil {
			return err
		}
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
