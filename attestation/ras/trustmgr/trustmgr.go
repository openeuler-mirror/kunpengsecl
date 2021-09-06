package trustmgr
/*
	trustmgr is used to register, save reports, extract base value, provide the newest report, etc.
 */
import (
	"errors"
	"fmt"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/dao"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

type TrustMgr struct {
}

var validator Validator
var extractor Extractor

// Validator will be implemented to validate integrity of report
type Validator interface {
	Validate(report *entity.Report) error
}
// Extractor will be implemented to extract base value from report
type Extractor interface {
	Extract(report *entity.Report) error
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
		psd := dao.CreatePostgreSqlDAO()
		defer psd.Destroy()
		err = psd.SaveReport(report)
		if err != nil {
			return err
		}
		return nil
	}
}

func Test() {
	fmt.Println("hello, this is trustmgr!")
}