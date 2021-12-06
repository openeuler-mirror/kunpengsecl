package verifier

/*
	verifier is used to verify trust status of target RAC.
*/
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

const (
	constDEFAULTTIMEOUT time.Duration = 100 * time.Second
	uint32Len                         = 4
	digestAlgIDLen                    = 2
	sha1DigestLen                     = 20
	sha256DigestLen                   = 32
	sha1AlgID                         = "0400"
	sha256AlgID                       = "0b00"
	event2SpecID                      = "Spec ID Event03"
	specLen                           = 16
	specStart                         = 32
	specEnd                           = 48
)

var validators []trustmgr.Validator
var extractors []trustmgr.Extractor
var verifiers []Verifier
var verifierMgr *VerifierMgr
var create []func() (interface{}, error)

type Verifier interface {
	Verify(baseValue *entity.MeasurementInfo, report *entity.Report) error
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

func (vm *VerifierMgr) Verify(baseValue *entity.MeasurementInfo, report *entity.Report) error {
	for i := range verifiers {
		err := verifiers[i].Verify(baseValue, report)
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
		if !isexist || bvvalue != rpvalue {
			return fmt.Errorf("PCR verification failed")
		}
	}
	return nil
}

func (pv *PCRVerifier) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	config := config.GetDefault(config.ConfServer)
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
	config := config.GetDefault(config.ConfServer)
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
	config := config.GetDefault(config.ConfServer)
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

func (bv *BIOSVerifier) Validate(report *entity.Report) error {
	pseudoPCR := make(map[uint32]string) //store PCR that will be figured out
	PCRid := make([]uint32, 0)

	//find bios manifest list
	var manifest entity.Manifest
	manifestCnt := 0
	for _, element := range report.Manifest {
		if element.Type == "bios" {
			manifest = element
			break
		}
		manifestCnt++
	}
	if manifestCnt == len(report.Manifest) {
		return fmt.Errorf("no bios manifest in report")
	}

	//use bios manifest to calculate pseudoPCR
	for _, item := range manifest.Items {
		//unmarshal manifest in report
		parsedManifest := new(entity.BIOSManifestItem)
		err := json.Unmarshal([]byte(item.Detail), parsedManifest)
		if err != nil {
			return fmt.Errorf("json unmarshal failed")
		}
		//initial
		temp, err2 := initpseudoPCR(pseudoPCR, parsedManifest, report.PcrInfo.AlgName, &PCRid)
		if err2 != nil {
			return fmt.Errorf("PCR Digest combine falied")
		}
		//combine
		err1 := combinePcrDigest(pseudoPCR, parsedManifest, report.PcrInfo.AlgName, temp)
		if err1 != nil {
			return fmt.Errorf("PCR Digest combine falied")
		}
		//calculate new pcr value
		h := sha256.New()
		h.Write(temp)
		newPCRBytes := h.Sum(nil)

		pseudoPCR[parsedManifest.Pcr] = hex.EncodeToString(newPCRBytes)
	}

	//compare report.PcrInfo.Values with pseudoPCR
	if len(report.PcrInfo.Values) != len(pseudoPCR) {
		return fmt.Errorf("bios validation failed: invalid bios")
	}
	for i := 0; i < len(pseudoPCR); i++ {
		if report.PcrInfo.Values[int(PCRid[i])] != pseudoPCR[PCRid[i]] {
			return fmt.Errorf("bios validation failed: invalid bios")
		}
	}

	return nil
}

func combinePcrDigest(pseudoPCR map[uint32]string, parsedManifest *entity.BIOSManifestItem, Algname string, temp []byte) error {
	prePCRBytes, err := hex.DecodeString(pseudoPCR[parsedManifest.Pcr])
	if err != nil {
		return fmt.Errorf("decode bios item digest failed")
	}
	for i := 0; i < len(prePCRBytes); i++ {
		temp[i] = prePCRBytes[i]
	}

	//continue to combine. find item that uses sha256, if there is no such item, return error
	var itemToUse entity.DigestItem
	itemCnt := 0
	for _, item := range parsedManifest.Digest.Item {
		var selectAlgID string
		if Algname == "sha1" {
			selectAlgID = sha1AlgID
		} else if Algname == "sha256" {
			selectAlgID = sha256AlgID
		} //expected to be extended (more algorithms)
		if item.AlgID == selectAlgID {
			itemToUse = item
			break
		}
		itemCnt++
	}
	if itemCnt == len(parsedManifest.Digest.Item) {
		return fmt.Errorf("no item can be used in bios manifest to calculate PCR")
	}
	newDigestBytes, err := hex.DecodeString(itemToUse.Item)
	if err != nil {
		return fmt.Errorf("decode bios item digest failed")
	}
	for i := 0; i < len(newDigestBytes); i++ {
		temp[len(prePCRBytes)+i] = newDigestBytes[i]
	}

	return nil
}

func initpseudoPCR(pseudoPCR map[uint32]string, parsedManifest *entity.BIOSManifestItem, algname string, PCRid *[]uint32) ([]byte, error) {
	var temp []byte

	if algname == "sha256" {
		temp = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		} //tpm 2.0, combination: 64 bytes
		if _, ok := pseudoPCR[parsedManifest.Pcr]; !ok {
			pseudoPCR[parsedManifest.Pcr] = "0000000000000000000000000000000000000000000000000000000000000000" //pcr: 32 bytes
			*PCRid = append(*PCRid, parsedManifest.Pcr)
		}
	} else if algname == "sha1" {
		temp = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		} //tpm 1.2, combination: 40 bytes
		if _, ok := pseudoPCR[parsedManifest.Pcr]; !ok {
			pseudoPCR[parsedManifest.Pcr] = "0000000000000000000000000000000000000000" //pcr: 20 bytes
			*PCRid = append(*PCRid, parsedManifest.Pcr)
		}
	} //expected to be extended (more algorithms)
	return temp, nil
}
