package trustmgr

/*
	trustmgr is used to register, save reports, extract base value, provide the newest report, etc.
*/
import (
	"errors"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
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
		err = handleBaseValue(report)
		if err != nil {
			return err
		}
		return nil
	}
}

func handleBaseValue(report *entity.Report) error {
	cfg := config.GetDefault(config.ConfServer)
	switch cfg.GetMgrStrategy() {
	// if mgrStrategy is auto-update, save base value of rac which in the update list
	case config.RasAutoUpdateStrategy:
		{
			err := recordAutoUpdateReport(report)
			if err != nil {
				return err
			}
		}

	// if mgrStrategy is auto, and if this is the first report of this RAC, extract base value
	case config.RasAutoStrategy:
		{
			isFirstReport, err := isFirstReport(report.ClientID)
			if err != nil {
				return err
			}
			baseValue := entity.MeasurementInfo{}
			if isFirstReport {
				extractor.Extract(report, &baseValue)
				err = SaveBaseValueById(report.ClientID, &baseValue)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
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
	// because isFirstReport is judged after saving report, len(reports) == 1
	if len(reports) == 1 {
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

func GetAllClientInfoByID(clientId int64) (map[string]string, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return map[string]string{}, err
	}
	return psd.SelectAllClientInfobyId(clientId)
}

func UpdateRegisterStatusById(clientId int64, isDeleted bool) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.UpdateRegisterStatusById(clientId, isDeleted)
}

func GetClientInfoByID(clientId int64, infoNames []string) (map[string]string, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return map[string]string{}, err
	}
	return psd.SelectClientInfobyId(clientId, infoNames)
}

func isMeasurementUpdate(oldMea *entity.MeasurementInfo, newMea *entity.MeasurementInfo) bool {
	// compare pcr info
	if isPcrInfoUpdate(&oldMea.PcrInfo, &newMea.PcrInfo) {
		return true
	}
	// compare manifest
	if isManifestUpdate(&oldMea.Manifest, &newMea.Manifest) {
		return true
	}
	return false
}

func isPcrInfoUpdate(oldPi *entity.PcrInfo, newPi *entity.PcrInfo) bool {
	if oldPi.AlgName != newPi.AlgName || len(oldPi.Values) != len(newPi.Values) {
		return true
	}
	for k, v := range oldPi.Values {
		if nv, ok := newPi.Values[k]; ok && nv == v {
			continue
		} else {
			return true
		}
	}
	return false
}

func isManifestUpdate(oldM *[]entity.Measurement, newM *[]entity.Measurement) bool {
	if len(*oldM) != len(*newM) {
		return true
	}
	for _, oldMeaItem := range *oldM {
		isExisted := false
		for _, newMeaItem := range *newM {
			// use oldMeaItem == newMeaItem is effective because varities in measurement are all string
			if oldMeaItem == newMeaItem {
				isExisted = true
			}
		}
		if !isExisted {
			return true
		}
	}
	return false

}

func recordAutoUpdateReport(report *entity.Report) error {
	cfg := config.GetDefault(config.ConfServer)
	// if all update
	isClientExist := false
	if cfg.GetAutoUpdateConfig().IsAllUpdate {
		isClientExist = true

	} else {
		clients := cfg.GetAutoUpdateConfig().UpdateClients
		for _, c := range clients {
			if report.ClientID == c {
				isClientExist = true
			}
		}
	}
	if isClientExist {
		newMea := entity.MeasurementInfo{}
		extractor.Extract(report, &newMea)
		oldMea, err := GetBaseValueById(report.ClientID)
		if err != nil {
			return err
		}
		if isMeasurementUpdate(oldMea, &newMea) {
			err = SaveBaseValueById(report.ClientID, &newMea)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
