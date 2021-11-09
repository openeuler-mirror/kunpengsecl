package verifier

/*
	verifier is used to verify trust status of target RAC.
*/
import (
	"fmt"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

var validators []trustmgr.Validator
var extractors []trustmgr.Extractor
var verifiers []Verifier
var verifierMgr *VerifierMgr
var create []func() (interface{}, error)

type Verifier interface {
	Verify(baseValue *entity.MeasurementInfo, report *entity.Report)
}

/*
	VerifierMgr is provided for other packages.
	it will call functions of validators, extractors, verifiers to process validating work.
*/
type VerifierMgr struct {
}

/*
	PCRVerifier will verify PCR values of trust report and base value
*/
type PCRVerifier struct {
}

type BIOSVerifier struct {
}

type IMAVerifier struct {
}

func (pv PCRVerifier) Validate() error {
	// TODO: validate process
	return nil
}

func createPCRVerifier() (interface{}, error) {
	pv := new(PCRVerifier)
	return pv, nil
}

func createBIOSVerifier() (interface{}, error) {
	bv := new(BIOSVerifier)
	return bv, nil
}

func createIMAVerifier() (interface{}, error) {
	iv := new(IMAVerifier)
	return iv, nil
}

func CreateVerifierMgr() (*VerifierMgr, error) {
	if verifierMgr == nil {
		verifierMgr = new(VerifierMgr)
		verifierMgr.init()
	}
	return verifierMgr, nil
}

/*
	if there are create functions in other packages , in their init function they can call RegisterFactoryMethod
	to register that.
*/
func RegisterFactoryMethod(c func() (interface{}, error)) {
	create = append(create, c)
}

func init() {
	RegisterFactoryMethod(createPCRVerifier)
	RegisterFactoryMethod(createBIOSVerifier)
	RegisterFactoryMethod(createIMAVerifier)
}

func (vm *VerifierMgr) init() error {
	for i := range create {
		obj, err := create[i]()
		if err != nil {
			return err
		}
		// generate global variety by obj type
		if e, ok := obj.(trustmgr.Extractor); ok {
			extractors = append(extractors, e)
		}
		if v, ok := obj.(trustmgr.Validator); ok {
			validators = append(validators, v)
		}
		if vf, ok := obj.(Verifier); ok {
			verifiers = append(verifiers, vf)
		}
	}
	return nil
}

/*
*VerifierMgr can call Validate to process Validate function of every validator in validators
 */
func (vm *VerifierMgr) Validate(report *entity.Report) error {
	for i := range validators {
		err := validators[i].Validate(report)
		if err != nil {
			return err
		}
	}
	return nil
}

func (vm *VerifierMgr) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	for i := range extractors {
		err := extractors[i].Extract(report, mInfo)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO: need update because PcrValue struct become map.
func (pv *PCRVerifier) Verify(baseValue *entity.MeasurementInfo, report *entity.Report) error {
	if baseValue == nil || report == nil {
		return fmt.Errorf("invalid input")
	}
	for id, bvvalue := range baseValue.PcrInfo.Values {
		rpvalue, isexist := report.PcrInfo.Values[id]
		if isexist == false || bvvalue != rpvalue {
			return fmt.Errorf("PCR verification failed")
		}
	}
	return nil
}

func (pv *PCRVerifier) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	config := config.GetDefault()
	pcrSelection := config.GetExtractRules().PcrRule.PcrSelection
	rpv := report.PcrInfo.Values
	if mInfo.PcrInfo.Values == nil {
		mInfo.PcrInfo.Values = make(map[int]string)
	}
	for _, n := range pcrSelection {
		if v, ok := rpv[n]; ok {
			mInfo.PcrInfo.Values[n] = v
		} else {
			return fmt.Errorf("extract failed. pcr number %v doesn't exist in this report", n)
		}
	}
	return nil
}

func (bv *BIOSVerifier) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	config := config.GetDefault()
	var biosNames []string
	var biosManifest entity.Manifest
	mRule := config.GetExtractRules().ManifestRules
	for _, rule := range mRule {
		if strings.ToLower(rule.MType) == "bios" {
			biosNames = rule.Name
			break
		}
	}
	for _, m := range report.Manifest {
		if strings.ToLower(m.Type) == "bios" {
			biosManifest = m
			break
		}
	}
	for _, bn := range biosNames {
		isFound := false
		for _, bmi := range biosManifest.Items {
			if bmi.Name == bn {
				isFound = true
				mInfo.Manifest = append(mInfo.Manifest, entity.Measurement{
					Type:  "bios",
					Name:  bn,
					Value: bmi.Value,
				})
				break
			}
		}
		if !isFound {
			return fmt.Errorf("extract failed. bios manifest name %v doesn't exist in this report", bn)
		}
	}
	return nil
}

func (iv *IMAVerifier) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	config := config.GetDefault()
	var imaNames []string
	var imaManifest entity.Manifest
	for _, rule := range config.GetExtractRules().ManifestRules {
		if strings.ToLower(rule.MType) == "ima" {
			imaNames = rule.Name
			break
		}
	}
	for _, m := range report.Manifest {
		if strings.ToLower(m.Type) == "ima" {
			imaManifest = m
			break
		}
	}
	for _, in := range imaNames {
		isFound := false
		for _, imi := range imaManifest.Items {
			if imi.Name == in {
				isFound = true
				mInfo.Manifest = append(mInfo.Manifest, entity.Measurement{
					Type:  "ima",
					Name:  in,
					Value: imi.Value,
				})
				break
			}
		}
		if !isFound {
			return fmt.Errorf("extract failed. ima manifest name %v doesn't exist in this report", in)
		}
	}
	return nil
}
