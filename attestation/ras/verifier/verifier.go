package verifier

/*
	verifier is used to verify trust status of target RAC.
*/
import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"github.com/google/go-tpm/tpm2"
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

func createPCRVerifier() (interface{}, error) {
	pv := new(PCRVerifier)
	return pv, nil
}

func (pv *PCRVerifier) Validate(report *entity.Report) error {
	//verify quote.signature
	signature := new(tpm2.Signature)
	err := json.Unmarshal(report.PcrInfo.Quote.Signature, signature)
	if err != nil {
		return fmt.Errorf("quote signature unmarshal failed")
	}
	//hash(quoted)
	h := sha256.New()
	h.Write(report.PcrInfo.Quote.Quoted)
	datahash := h.Sum(nil)
	//get public key
	regclient, err := trustmgr.GetRegisterClientById(report.ClientID)
	if err != nil {
		return fmt.Errorf("get register client information failed")
	}
	certificate, err := pca.DecodeCert(regclient.AkCertificate)
	if err != nil {
		return fmt.Errorf("get register client certificate failed")
	}
	err = rsa.VerifyPKCS1v15(certificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, datahash, signature.RSA.Signature)
	if err != nil {
		return fmt.Errorf("PCR validation failed: signature verification failed")
	}

	//use PCRselection to calculate PCRdigest
	parsedQuote, err := tpm2.DecodeAttestationData(report.PcrInfo.Quote.Quoted)
	if err != nil {
		return fmt.Errorf("DecodeAttestationData failed")
	}
	//combine all pcrs
	temp := []byte{}
	for _, PCRid := range parsedQuote.AttestedQuoteInfo.PCRSelection.PCRs {
		pcrValueBytes, err := hex.DecodeString(report.PcrInfo.Values[PCRid])
		if err != nil {
			return fmt.Errorf("DecodeString failed")
		}
		temp = append(temp, pcrValueBytes...)
	}
	//calculate new pcr digest
	h1 := sha256.New()
	h1.Write(temp)
	newDigestBytes := h1.Sum(nil)

	//compare newDigest with quote.digest
	if len(newDigestBytes) != len(parsedQuote.AttestedQuoteInfo.PCRDigest) {
		return fmt.Errorf("PCR validate failed")
	}
	for i := 0; i < len(newDigestBytes); i++ {
		if parsedQuote.AttestedQuoteInfo.PCRDigest[i] != newDigestBytes[i] {
			return fmt.Errorf("PCR validate failed")
		}
	}
	return nil
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

func (bv *BIOSVerifier) Verify(baseValue *entity.MeasurementInfo, report *entity.Report) error {
	extractedBIOS := &entity.MeasurementInfo{}
	err := bv.Extract(report, extractedBIOS)
	if err != nil {
		return fmt.Errorf("manifest extraction failed")
	}
	manifest, err := selectManifest(baseValue.Manifest, "bios")
	if err != nil {
		return fmt.Errorf("bios extraction failed")
	}
	// compare
	if trustmgr.IsManifestUpdate(&manifest, &extractedBIOS.Manifest) {
		return fmt.Errorf("bios manifest verification failed")
	}

	return nil
}

func (iv *IMAVerifier) Verify(baseValue *entity.MeasurementInfo, report *entity.Report) error {
	extractedIMA := &entity.MeasurementInfo{}
	err := iv.Extract(report, extractedIMA)
	if err != nil {
		return fmt.Errorf("manifest extraction failed")
	}
	manifest, err := selectManifest(baseValue.Manifest, "ima")
	if err != nil {
		return fmt.Errorf("bios extraction failed")
	}
	// compare
	if trustmgr.IsManifestUpdate(&manifest, &extractedIMA.Manifest) {
		return fmt.Errorf("ima manifest verification failed")
	}

	return nil
}

func selectManifest(basemanifest []entity.Measurement, manifestType string) ([]entity.Measurement, error) {
	// find bios manifest list from basevalue.manifest
	manifest := []entity.Measurement{}
	for _, element := range basemanifest {
		if element.Type == manifestType {
			manifest = append(manifest, element)
		}
	}
	if len(manifest) == 0 {
		return nil, fmt.Errorf("no item has been found")
	}
	return manifest, nil
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

type PCRExtender interface {
	ExtendPCR(id uint32, v string) error
}

type pseudoPCRExtender struct {
	pcrs    [24][]byte
	algname string
	newHash func() hash.Hash
	lenHash int
}

func (pe *pseudoPCRExtender) ExtendPCR(id uint32, v string) error {
	temp := bytes.NewBuffer(pe.pcrs[id])

	newDigestBytes, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("decode digest failed")
	}
	_, err = temp.Write(newDigestBytes)
	if err != nil {
		return fmt.Errorf("concatenate digests failed")
	}

	//calculate new pcr value
	h := pe.newHash()
	if h == nil {
		return fmt.Errorf("unsupported algorithm")
	}
	h.Write(temp.Bytes())
	pe.pcrs[id] = h.Sum(nil)
	return nil
}

func createPseudoPCRExtender(algname string) *pseudoPCRExtender {
	pe := pseudoPCRExtender{algname: algname}
	switch pe.algname {
	case "sha256":
		pe.newHash = sha256.New
		pe.lenHash = sha256DigestLen
	case "sha1":
		pe.newHash = sha1.New
		pe.lenHash = sha1DigestLen
	default:
		return nil
	}

	for i := range pe.pcrs {
		pe.pcrs[i] = make([]byte, pe.lenHash)
	}
	return &pe
}

func (bv *BIOSVerifier) Validate(report *entity.Report) error {
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
	pseudoPCR := createPseudoPCRExtender(config.GetDefault(config.ConfServer).GetDigestAlgorithm())
	if pseudoPCR == nil {
		return fmt.Errorf("create pseudo PCRs failed")
	}
	err := ExtendPCRForBIOSItems(pseudoPCR, manifest.Items)
	if err != nil {
		return fmt.Errorf("pcr extend failed (use bios)")
	}

	for i := 0; i < 8; i++ {
		if report.PcrInfo.Values[i] != hex.EncodeToString(pseudoPCR.pcrs[i]) {
			return fmt.Errorf("bios validation failed: invalid bios")
		}
	}

	return nil
}

func ExtendPCRForBIOSItems(pe PCRExtender, Items []entity.ManifestItem) error {
	//use bios manifest to calculate pseudoPCR
	for _, item := range Items {
		//unmarshal manifest in report
		parsedManifest := new(entity.BIOSManifestItem)
		err := json.Unmarshal([]byte(item.Detail), parsedManifest)
		if err != nil {
			return fmt.Errorf("json unmarshal failed")
		}
		//combine & calculate new pcr value
		err1 := pe.ExtendPCR(parsedManifest.Pcr, item.Value)
		if err1 != nil {
			return fmt.Errorf("PCR Digest combine falied")
		}
	}
	return nil
}

func ExtendPCRForIMAItems(pe PCRExtender, Items []entity.ManifestItem, changedPCRid *[]uint32) error {
	//use ima manifest to calculate pseudoPCR
	for _, item := range Items {
		//unmarshal manifest in report
		parsedManifest := new(entity.IMAManifestItem)
		err := json.Unmarshal([]byte(item.Detail), parsedManifest)
		if err != nil {
			return fmt.Errorf("json unmarshal failed")
		}
		//combine & calculate new pcr value
		pcrid, err := strconv.Atoi(parsedManifest.Pcr)
		if err != nil {
			return fmt.Errorf("PCR type conversion failed")
		}
		err = pe.ExtendPCR(uint32(pcrid), item.Value)
		if err != nil {
			return fmt.Errorf("PCR Digest combine falied")
		}
		// store pcrs id that have been changed
		cnt := 0
		for _, p := range *changedPCRid {
			if p == uint32(pcrid) {
				break
			}
			cnt++
		}
		if cnt == len(*changedPCRid) {
			*changedPCRid = append(*changedPCRid, uint32(pcrid))
		}
	}
	return nil
}

func (iv *IMAVerifier) Validate(report *entity.Report) error {
	// find ima manifest list
	var manifest entity.Manifest
	manifestCnt := 0
	for _, element := range report.Manifest {
		if element.Type == "ima" {
			manifest = element
			break
		}
		manifestCnt++
	}
	if manifestCnt == len(report.Manifest) {
		return fmt.Errorf("no ima manifest in report")
	}

	// use pcr0-7 in report to calculate boot_aggregate
	temp := []byte{}
	for i := 0; i < 8; i++ {
		pcrValueBytes, err := hex.DecodeString(report.PcrInfo.Values[i])
		if err != nil {
			return fmt.Errorf("DecodeString failed")
		}
		temp = append(temp, pcrValueBytes...)
	}
	h1 := sha1.New()
	h1.Write(temp)
	newBootAggreBytes := h1.Sum(nil)

	// compare boot_aggregate with ima[0].boot_aggregate
	if hex.EncodeToString(newBootAggreBytes) != manifest.Items[0].Value {
		return fmt.Errorf("ima manifest validation falied")
	}

	// use ima manifest to calculate pseudoPCR
	changedPCRid := []uint32{}
	pseudoPCR := createPseudoPCRExtender("sha1")
	if pseudoPCR == nil {
		return fmt.Errorf("create pseudo PCRs failed")
	}
	err := ExtendPCRForIMAItems(pseudoPCR, manifest.Items, &changedPCRid)
	if err != nil {
		return fmt.Errorf("pcr extend failed (use ima)")
	}

	//compare pseudoPCR with pcrs in report
	for _, pcrindex := range changedPCRid {
		if report.PcrInfo.Values[int(pcrindex)] != hex.EncodeToString(pseudoPCR.pcrs[pcrindex]) {
			return fmt.Errorf("ima validation failed: invalid ima")
		}
	}

	return nil
}
