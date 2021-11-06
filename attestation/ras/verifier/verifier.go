package verifier

/*
	verifier is used to verify trust status of target RAC.
*/
import (
	"fmt"

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

func (pv PCRVerifier) Validate() error {
	// TODO: validate process
	return nil
}

func createPCRVerifier() (interface{}, error) {
	pv := new(PCRVerifier)
	return pv, nil
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
