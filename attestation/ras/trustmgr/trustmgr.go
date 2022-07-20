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
			if isFirstReport && extractor != nil {
				err = extractor.Extract(report, &baseValue)
				if err != nil {
					return err
				}
				err = SaveBaseValueById(report.ClientID, &baseValue)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func RegisterClient(clientInfo *entity.ClientInfo, ic []byte, registered bool) (int64, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return 0, err
	}
	clientId, err := psd.RegisterClient(clientInfo, ic, registered)
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

func UpdateRegisterClient(rc *entity.RegisterClient) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.UpdateRegisterClient(rc)
}

func AddContainer(c *entity.Container) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.InsertContainer(c)
}

func AddContainerBaseValue(cbv *entity.ContainerBaseValue) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.InsertContainerBaseValue(cbv)
}

func GetContainerByUUId(uuID string) (*entity.Container, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectContainerByUUId(uuID)
}

func GetContainerBaseValueByUUId(uuID string) (*entity.ContainerBaseValue, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectContainerBaseValueByUUId(uuID)
}

func UpdateContainerStatusByUUId(uuID string, isDeleted bool) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.UpdateContainerRegistryStatusByUUId(uuID, isDeleted)
}

func GetAllContainerUUIds() ([]string, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectAllContainerUUIds()
}

func GetDeviceById(deviceId int64) (*entity.PcieDevice, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectDeviceById(deviceId)
}

func GetDeviceBaseValueById(deviceId int64) (*entity.PcieBaseValue, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectDeviceBaseValueById(deviceId)
}

func AddDevice(c *entity.PcieDevice) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.InsertDevice(c)
}

func AddDeviceBaseValue(pbv *entity.PcieBaseValue) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.InsertDeviceBaseValue(pbv)
}

func UpdateDeviceStatusById(deviceId int64, isDeleted bool) error {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return err
	}
	return psd.UpdateDeviceRegistryStatusById(deviceId, isDeleted)
}

func GetAllDeviceIds() ([]int64, error) {
	psd, err := getPostgreSQLDAO()
	if err != nil {
		return nil, err
	}
	return psd.SelectAllDeviceIds()
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
	if IsManifestUpdate(&oldMea.Manifest, &newMea.Manifest) {
		return true
	}
	return false
}

func isPcrInfoUpdate(oldPi *entity.PcrInfo, newPi *entity.PcrInfo) bool {
	if len(oldPi.Values) != len(newPi.Values) {
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

func IsManifestUpdate(oldM *[]entity.Measurement, newM *[]entity.Measurement) bool {
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

func isClientAutoUpdate(clientID int64) bool {
	cfg := config.GetDefault(config.ConfServer)
	// if all update
	if cfg.GetAutoUpdateConfig().IsAllUpdate {
		return true
	}
	clients := cfg.GetAutoUpdateConfig().UpdateClients
	for _, c := range clients {
		if clientID == c {
			return true
		}
	}
	return false
}

func recordAutoUpdateReport(report *entity.Report) error {
	if isClientAutoUpdate(report.ClientID) && extractor != nil {
		newMea := entity.MeasurementInfo{}
		err := extractor.Extract(report, &newMea)
		if err != nil {
			return err
		}
		oldMea, err := GetBaseValueById(report.ClientID)
		if err != nil {
			err = SaveBaseValueById(report.ClientID, &newMea)
			if err != nil {
				return err
			}
		} else if isMeasurementUpdate(oldMea, &newMea) {
			err = SaveBaseValueById(report.ClientID, &newMea)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
