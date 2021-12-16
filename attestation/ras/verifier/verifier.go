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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"log"
	"strconv"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"github.com/google/go-tpm/tpm2"
)

const (
	uint32Len         = 4
	sha1DigestLen     = 20
	sha256DigestLen   = 32
	sha1AlgID         = "0400"
	sha256AlgID       = "0b00"
	sha1AlgStr        = "sha1"
	sha256AlgStr      = "sha256"
	imaStr            = "ima"
	imangStr          = "ima-ng"
	imaItemNameLenMax = 255
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
	certificate, _, err := pca.DecodeKeyCertFromPEM([]byte(regclient.AkCertificate))
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
	if len(manifest) == 0 {
		return nil
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
	manifest, err := selectManifest(baseValue.Manifest, imaStr)
	if err != nil {
		return fmt.Errorf("ima extraction failed")
	}
	if len(manifest) == 0 {
		return nil
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
		log.Printf("no item has been found")
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
			log.Printf("extract failed. bios manifest name %v doesn't exist in this report", bn)
		}
	}
	return nil
}

func (iv *IMAVerifier) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	config := config.GetDefault(config.ConfServer)
	var imaNames []string
	var imaManifest entity.Manifest
	for _, rule := range config.GetExtractRules().ManifestRules {
		if strings.ToLower(rule.MType) == imaStr {
			imaNames = rule.Name
			break
		}
	}
	for _, m := range report.Manifest {
		if strings.ToLower(m.Type) == imaStr {
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
					Type:  imaStr,
					Name:  in,
					Value: imi.Value,
				})
				break
			}
		}
		if !isFound {
			log.Printf("extract failed. ima manifest name %v doesn't exist in this report", in)
		}
	}
	return nil
}

type PCRExtender interface {
	ExtendPCR(id uint32, v string) error
	ExtendPCRRaw(id uint32, v []byte) error
}

type pseudoPCRExtender struct {
	pcrs    [24][]byte
	algname string
	newHash func() hash.Hash
	lenHash int
}

func (pe *pseudoPCRExtender) ExtendPCRRaw(id uint32, v []byte) error {
	//calculate new pcr value
	h := pe.newHash()
	if h == nil {
		return fmt.Errorf("unsupported algorithm")
	}
	h.Write(pe.pcrs[id])
	h.Write(v)
	pe.pcrs[id] = h.Sum(nil)
	return nil
}

func (pe *pseudoPCRExtender) ExtendPCR(id uint32, v string) error {
	newDigestBytes, err := hex.DecodeString(v)
	if err != nil {
		return fmt.Errorf("decode digest failed")
	}
	return pe.ExtendPCRRaw(id, newDigestBytes)
}

func matchHashAlgNewFunc(alg string) (func() hash.Hash, int) {
	switch alg {
	case sha256AlgStr:
		return sha256.New, sha256DigestLen
	case sha1AlgStr:
		return sha1.New, sha1DigestLen
	default:
		return nil, 0
	}
}

func createPseudoPCRExtender(algname string) *pseudoPCRExtender {
	pe := pseudoPCRExtender{algname: algname}
	pe.newHash, pe.lenHash = matchHashAlgNewFunc(pe.algname)
	if pe.newHash == nil {
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
		return fmt.Errorf("bios manifest validator create pseudo PCRs failed")
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

func parseIMAManifestItem(detail string) (*entity.IMAManifestItem, error) {
	parsedManifest := new(entity.IMAManifestItem)
	err := json.Unmarshal([]byte(detail), parsedManifest)
	return parsedManifest, err
}

type TemplateHasher interface {
	Hash(item *entity.IMAManifestItem) ([]byte, error)
}

type TemplateValidator interface {
	Validate(item *entity.IMAManifestItem) error
}

type TemplateHandler interface {
	TemplateHasher
	TemplateValidator
}

type TemplateHandlerBase struct {
	algHash         string
	newHash         func() hash.Hash
	lenHash         int
	algValidate     string
	newHashValidate func() hash.Hash
	lenHashValidate int
}

type IMATemplateHandler struct {
	TemplateHandlerBase
}

type IMANGTemplateHandler struct {
	TemplateHandlerBase
}

func (imaTH *IMATemplateHandler) Hash(item *entity.IMAManifestItem) ([]byte, error) {
	return hex.DecodeString(item.TemplateHash)
}

func (imaTH *IMATemplateHandler) updateFileDigest(h hash.Hash, fileDigest string) {
	bHash := make([]byte, hex.DecodedLen(len(fileDigest)))
	hex.Decode(bHash, []byte(fileDigest))
	h.Write(bHash)
}

func (imaTH *IMATemplateHandler) updateFileName(h hash.Hash, fileName string) {
	h.Write([]byte(fileName))
	if len(fileName) < imaItemNameLenMax+1 {
		h.Write(make([]byte, imaItemNameLenMax+1-len(fileName)))
	}
}

func (imaTH *IMATemplateHandler) Validate(item *entity.IMAManifestItem) error {
	h := imaTH.newHashValidate()
	if h == nil {
		return fmt.Errorf("calculate ima template hash failed")
	}

	imaTH.updateFileDigest(h, item.FiledataHash)
	imaTH.updateFileName(h, item.FilenameHint)
	th := hex.EncodeToString(h.Sum(nil))

	if th != item.TemplateHash {
		return fmt.Errorf("ima template hash verification failed")
	}

	return nil
}

func createTemplateHandlerBase(algname string) *TemplateHandlerBase {
	imaTH := TemplateHandlerBase{algHash: algname, algValidate: sha1AlgStr}
	imaTH.newHash, imaTH.lenHash = matchHashAlgNewFunc(imaTH.algHash)
	if imaTH.newHash == nil {
		return nil
	}
	imaTH.newHashValidate, imaTH.lenHashValidate = matchHashAlgNewFunc(imaTH.algValidate)
	if imaTH.newHash == nil {
		return nil
	}
	return &imaTH
}

func createIMATemplateHandler(algname string) *IMATemplateHandler {
	imaTH := IMATemplateHandler{TemplateHandlerBase{algHash: algname, algValidate: sha1AlgStr}}
	imaTH.newHash, imaTH.lenHash = matchHashAlgNewFunc(imaTH.algHash)
	if imaTH.newHash == nil {
		return nil
	}
	imaTH.newHashValidate, imaTH.lenHashValidate = matchHashAlgNewFunc(imaTH.algValidate)
	if imaTH.newHash == nil {
		return nil
	}
	return &imaTH
}

func (imaTH *IMANGTemplateHandler) Hash(item *entity.IMAManifestItem) ([]byte, error) {
	h := imaTH.newHash()
	if h == nil {
		return nil, fmt.Errorf("calculate ima-ng template hash failed")
	}

	imaTH.updateFileDigest(h, item.FiledataHash)
	imaTH.updateFileName(h, item.FilenameHint)
	return h.Sum(nil), nil
}

func (imaTH *IMANGTemplateHandler) Validate(item *entity.IMAManifestItem) error {
	h := imaTH.newHashValidate()
	if h == nil {
		return fmt.Errorf("calculate ima-ng template hash failed")
	}

	imaTH.updateFileDigest(h, item.FiledataHash)
	imaTH.updateFileName(h, item.FilenameHint)
	th := hex.EncodeToString(h.Sum(nil))

	if th != item.TemplateHash {
		return fmt.Errorf("ima-ng template hash verification failed")
	}

	return nil
}

func (imaTH *IMANGTemplateHandler) updateFileDigest(h hash.Hash, fileDigestNG string) {
	idx := strings.Index(fileDigestNG, ":")
	b := bytes.Buffer{}
	b.WriteString(fileDigestNG[:idx+1])
	b.WriteByte(0)

	bHash := make([]byte, hex.DecodedLen(len(fileDigestNG[idx+1:])))
	hex.Decode(bHash, []byte(fileDigestNG)[idx+1:])
	b.Write(bHash)

	bLen := make([]byte, uint32Len)
	binary.LittleEndian.PutUint32(bLen, uint32(b.Len()))

	h.Write(bLen)
	h.Write(b.Bytes())
}

func (imaTH *IMANGTemplateHandler) updateFileName(h hash.Hash, fileNameNG string) {
	bLen := make([]byte, uint32Len)
	binary.LittleEndian.PutUint32(bLen, uint32(len(fileNameNG)+1))

	h.Write(bLen)
	h.Write([]byte(fileNameNG))
	h.Write([]byte{0})
}

func createIMANGTemplateHandler(algname string) *IMANGTemplateHandler {
	base := createTemplateHandlerBase(algname)
	if base == nil {
		return nil
	}
	return &IMANGTemplateHandler{*base}
}

func createTemplateHandler(hashAlg string, templateName string) TemplateHandler {
	switch templateName {
	case imaStr:
		return createIMATemplateHandler(hashAlg)
	case imangStr:
		return createIMANGTemplateHandler(hashAlg)
	default:
		return nil
	}
}

func ExtendPCRForIMAItemsWithTemplateHandler(pe PCRExtender, th TemplateHandler, items []entity.ManifestItem) (map[int]bool, error) {
	changedPCR := map[int]bool{}

	// use ima manifest to calculate pseudoPCR
	for _, item := range items {
		// unmarshal manifest in report
		parsedManifest, err := parseIMAManifestItem(item.Detail)
		if err != nil {
			return nil, fmt.Errorf("json unmarshal failed")
		}
		// validate item template
		err = th.Validate(parsedManifest)
		if err != nil {
			return nil, fmt.Errorf("item template validation failed, %v", err)
		}
		// caculate template hash
		hash, err := th.Hash(parsedManifest)
		if err != nil {
			return nil, fmt.Errorf("item template hash calculation failed, %v", err)
		}
		// combine & calculate new pcr value
		pcrid, err := strconv.Atoi(parsedManifest.Pcr)
		if err != nil {
			return nil, fmt.Errorf("PCR type conversion failed")
		}
		err = pe.ExtendPCRRaw(uint32(pcrid), hash)
		if err != nil {
			return nil, fmt.Errorf("PCR Digest combine falied")
		}
		// store pcrs id that have been changed
		changedPCR[pcrid] = true
	}
	return changedPCR, nil
}

func ExtendPCRForIMAItems(hashAlg string, pe PCRExtender, Items []entity.ManifestItem) (map[int]bool, error) {
	// handle ima manifest validation in ima template specific ways
	templateName := getIMATemplateName(&Items[0])

	imaTH := createTemplateHandler(hashAlg, templateName)
	if imaTH == nil {
		return nil, fmt.Errorf("create ima-ng template hasher failed")
	}
	return ExtendPCRForIMAItemsWithTemplateHandler(pe, imaTH, Items)
}

func (iv *IMAVerifier) Validate(report *entity.Report) error {
	alg := config.GetDefault(config.ConfServer).GetDigestAlgorithm()
	// find ima manifest list
	var manifest *entity.Manifest
	manifestCnt := 0
	for _, element := range report.Manifest {
		if element.Type == imaStr {
			manifest = &element
			break
		}
		manifestCnt++
	}
	if manifestCnt == len(report.Manifest) {
		return fmt.Errorf("no ima manifest in report")
	}

	// handle ima manifest validation in ima template specific ways
	imaTemplateName := getIMATemplateName(&manifest.Items[0])
	switch imaTemplateName {
	case imaStr:
		return validateIMATemplateIMA(alg, &report.PcrInfo, manifest)
	case imangStr:
		return validateIMATemplateIMANG(alg, &report.PcrInfo, manifest)
	default:
		return fmt.Errorf("ima validation failed: invalid template, %s", imaTemplateName)
	}
}

func getIMATemplateName(item *entity.ManifestItem) string {
	parsedManifest, err := parseIMAManifestItem(item.Detail)
	if err != nil {
		return "N/A"
	}
	return parsedManifest.TemplateName
}

func validateIMABootAggregate(h hash.Hash, pcrInfo *entity.PcrInfo, aggregateValue string) error {
	// use pcr0-7 in report to calculate boot_aggregate
	for i := 0; i < 8; i++ {
		pcrValueBytes, err := hex.DecodeString(pcrInfo.Values[i])
		if err != nil {
			return fmt.Errorf("DecodeString failed")
		}
		h.Write(pcrValueBytes)
	}
	newBootAggreBytes := h.Sum(nil)

	// compare boot_aggregate with given boot aggregate string
	if hex.EncodeToString(newBootAggreBytes) != aggregateValue {
		return fmt.Errorf("boot aggregate validation falied")
	}

	return nil
}

func validateIMANGBootAggregate(h hash.Hash, pcrInfo *entity.PcrInfo, aggregateValue string) error {
	// remove the [alg:] prefix
	idx := strings.Index(aggregateValue, ":")
	agValue := aggregateValue[idx+1:]

	return validateIMABootAggregate(h, pcrInfo, agValue)
}

func newHash(alg string) hash.Hash {
	newHash, _ := matchHashAlgNewFunc(alg)
	if newHash != nil {
		return newHash()
	}
	return nil
}

func validateIMATemplateIMA(hashAlg string, pcrInfo *entity.PcrInfo, manifest *entity.Manifest) error {
	if hashAlg != sha1AlgStr {
		return fmt.Errorf("non-supported hash alg with ima-template: %s", hashAlg)
	}
	h := sha1.New()
	if h == nil {
		return fmt.Errorf("out of memory")
	}
	err := validateIMABootAggregate(h, pcrInfo, manifest.Items[0].Value)
	if err != nil {
		return fmt.Errorf("ima manifest validation falied: %v", err)
	}

	// use ima manifest to calculate pseudoPCR
	pseudoPCR := createPseudoPCRExtender(hashAlg)
	if pseudoPCR == nil {
		return fmt.Errorf("ima validator create pseudo PCRs failed")
	}
	changedPCRid, err := ExtendPCRForIMAItems(hashAlg, pseudoPCR, manifest.Items)
	if err != nil {
		return fmt.Errorf("pcr extend failed (use ima): %v", err)
	}

	//compare pseudoPCR with pcrs in report
	for pcrindex := range changedPCRid {
		if pcrInfo.Values[pcrindex] != hex.EncodeToString(pseudoPCR.pcrs[pcrindex]) {
			return fmt.Errorf("ima validation failed: invalid ima")
		}
	}

	return nil
}

func validateIMATemplateIMANG(hashAlg string, pcrInfo *entity.PcrInfo, manifest *entity.Manifest) error {
	h := newHash(hashAlg)
	if h == nil {
		return fmt.Errorf("out of memory or not supported hash algorithm")
	}
	err := validateIMANGBootAggregate(h, pcrInfo, manifest.Items[0].Value)
	if err != nil {
		return fmt.Errorf("ima-ng manifest validation falied: %v", err)
	}

	// use ima manifest to calculate pseudoPCR
	pseudoPCR := createPseudoPCRExtender(hashAlg)
	if pseudoPCR == nil {
		return fmt.Errorf("ima-ng validator create pseudo PCRs failed")
	}
	changedPCRid, err := ExtendPCRForIMAItems(hashAlg, pseudoPCR, manifest.Items)
	if err != nil {
		return fmt.Errorf("pcr extend failed (use ima)")
	}

	//compare pseudoPCR with pcrs in report
	for pcrindex := range changedPCRid {
		if pcrInfo.Values[pcrindex] != hex.EncodeToString(pseudoPCR.pcrs[pcrindex]) {
			return fmt.Errorf("ima validation failed: invalid ima")
		}
	}

	return nil
}
