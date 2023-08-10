/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2022-01-18
Description: type define and const values for common useage.
*/

// typdefs package defines common const/type/var for both ras and rac.
// DON'T includes other parts in it, just imports 3rd part packages.
package typdefs

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gemalto/kmip-go"
	"github.com/tjfoc/gmsm/sm3"
)

// Command value is used for nextAction which determind what to do for RAC.
const (
	CmdSendConfig uint64 = 1 << iota // send new configuration to RAC.
	CmdGetReport                     // get a new trust report from RAC.
	CmdNone       uint64 = 0         // clear all pending commands.
)

// definitions for global use.
const (
	StrPcr          = "pcr"
	StrBios         = "bios"
	StrIma          = "ima"
	StrImaNg        = "ima-ng"
	StrHost         = "host"
	StrContainer    = "container"
	StrDevice       = "device"
	Sha1DigestLen   = 20
	Sha256DigestLen = 32
	SM3DigestLen    = 32
	Sha1AlgStr      = "sha1"
	Sha256AlgStr    = "sha256"
	Sm3AlgStr       = "sm3"
	PcrMaxNum       = 24
	StrTimeFormat   = `2006-01-02 15:04:05.999 -07:00`
	DigestAlgStr    = "digestAlg"
	TaBaseLen       = 64
)

// definitions for BIOS/IMA log parse used only in this package.
const (
	uint32Len         = 4
	digestAlgIDLen    = 2
	sha1AlgID         = "0400"
	sha256AlgID       = "0b00"
	sm3AlgID          = "1200"
	event2SpecID      = "Spec ID Event03"
	specLen           = 16
	specStart         = 32
	specEnd           = 48
	algNumStart       = 56
	algNumEnd         = 60
	algNumLen         = 4
	algAndSizeStart   = 60
	algIDLen          = 2
	algDigestSizeLen  = 2
	ImaLogItemNum     = 5
	BiosLogItemNum    = 6
	SM3BiosLogItemNum = 7
	naStr             = "N/A"
	imaItemNameLenMax = 255
)

type (
	// TrustReport stores the original trust report data
	// sending from raagent to ras.
	TrustReport struct {
		ClientID   int64
		Nonce      uint64
		ClientInfo string
		Quoted     []byte
		Signature  []byte
		Manifests  []Manifest
		TaReports  map[string][]byte // map[uuid]TaReport
	}

	// Manifest stores the pcr/bios/ima log part of trust report.
	Manifest struct {
		Key   string // pcr/bios/ima
		Value []byte // log file content
	}

	// ClientRow stores one record of client basic information
	// in database table `client`.
	ClientRow struct {
		ID         int64
		RegTime    time.Time
		Registered bool
		Info       string
		IKCert     string
	}

	// ReportRow stores one record of trust report information
	// in database table `report`.
	ReportRow struct {
		ID         int64
		ClientID   int64
		CreateTime time.Time
		Validated  bool
		Trusted    bool
		Quoted     string // hex code of quote
		Signature  string // json string of signature info
		PcrLog     string // text format of pcr log
		BiosLog    string // store the text format of bios log
		ImaLog     string // original text format of ima log
	}

	// TaReportRow stores one record of TA trust report information
	// in database table `tareport`.
	TaReportRow struct {
		ID         int64
		ClientID   int64
		CreateTime time.Time
		Validated  bool
		Trusted    bool
		Uuid       string
		Value      []byte
	}

	// BaseRow stores one record of the base information in database
	// table `base`, which is specified by customer and will be used
	// to verify trust report.
	BaseRow struct {
		ID         int64
		ClientID   int64
		BaseType   string
		Uuid       string
		CreateTime time.Time
		Name       string
		Enabled    bool
		Pcr        string
		Bios       string
		Ima        string
		Verified   bool
		Trusted    bool
	}

	// TaBaseRow stores one record of the TA base information in database
	// table `tabase`, which is specified by customer and will be used
	// to verify TA trust report.
	TaBaseRow struct {
		ID         int64
		ClientID   int64
		Uuid       string
		CreateTime time.Time
		Name       string
		Valueinfo  []byte
	}

	// KeyinfoRow stores one record of the key information in database
	// table `keyinfo`.
	KeyinfoRow struct {
		ID         int64
		TaID       string
		KeyID      string
		Ciphertext string
	}

	// PubKeyinfoRow stores one record of the public key cert information in database
	// table `pubkeyinfo`.
	PubKeyinfoRow struct {
		ID         int64
		DeviceID   int64
		PubKeyCert string
	}
)

type (
	// ExtractRules corresponds to basevalue-extract-rules in config
	ExtractRules struct {
		// pcr extract rule
		PcrRule PcrRule `mapstructure:"pcrinfo"`
		// manifest extract rule
		ManifestRules []ManifestRule `mapstructure:"manifest"`
	}
	// PcrRule means pcr extract rule
	PcrRule struct {
		// pcr number slice which is expected to be extracted
		PcrSelection []int `mapstructure:"pcrselection"`
	}
	// ManifestRule means manifest extract rule
	ManifestRule struct {
		// manifest type : bios or ima
		MType string `mapstructure:"type"`
		// manifest item name which is expected to be extracted
		Name []string `mapstructure:"name"`
	}
)

var (
	// NewLine is used to change to a new line
	NewLine = []byte("\n")
	// Space is used to represent a space
	Space = []byte(" ")
	// Colon is used to represent a colon
	Colon = []byte(":")
	// SpaceZero is used to represent
	SpaceZero = " \x00"
	// EmptyBase means a empty Baserow
	EmptyBase = BaseRow{}

	// ErrPcrIndexWrong means pcr index wrong error
	ErrPcrIndexWrong = errors.New("pcr index wrong")
	// ErrImaLogFormatWrong means ima log format wrong error
	ErrImaLogFormatWrong = errors.New("ima log format wrong")
	// ErrBiosLogFormatWrong means bios log format wrong error
	ErrBiosLogFormatWrong = errors.New("bios log format wrong")
	// ErrBiosAggregateFail means bios aggregate not match error
	ErrBiosAggregateFail = errors.New("bios aggregate not match")
	// ErrValidateIMAFail means validate ima log fail
	ErrValidateIMAFail = errors.New("validate ima log fail")

	// client database handle errors
	// ErrParameterWrong means parameter is wrong
	ErrParameterWrong = errors.New("parameter is wrong")
	// ErrAlgorithmWrong means report algorithm is wrong
	ErrAlgorithmWrong = errors.New("report algorithm is wrong")
	// ErrConnectFailed means create connection failed
	ErrConnectFailed = errors.New("create connection failed")
	// ErrDoesnotRegistered means client does not registered
	ErrDoesnotRegistered = errors.New("client does not registered")
	// ErrAlreadyRegistered means client already registered
	ErrAlreadyRegistered = errors.New("client already registered")
	// ErrIKCertNull means client ik cert null
	ErrIKCertNull = errors.New("client ik cert null")
	// ErrNonceNotMatch means report nonce not match
	ErrNonceNotMatch = errors.New("report nonce not match")
	// ErrPCRNotMatch means report pcr not match
	ErrPCRNotMatch = errors.New("report pcr not match")
	// ErrNotSupportAlg means algorithm is not supported
	ErrNotSupportAlg = errors.New("algorithm is not supported")
	// ErrNotMatchAlg means algorithms in ima measurement and ras don't match
	ErrNotMatchAlg = errors.New("algorithms in ima measurement and ras don't match")

	// SupportAlgAndLenMap means the pairing of
	// supported algorithms and algorithm lengths
	SupportAlgAndLenMap = map[string]int{
		Sha1AlgStr:   Sha1DigestLen,
		Sha256AlgStr: Sha256DigestLen,
		Sm3AlgStr:    SM3DigestLen,
	}
)

// GetIP returns the host ipv4 address
func GetIP() string {
	netIfs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for i := 0; i < len(netIfs); i++ {
		if (netIfs[i].Flags & net.FlagUp) != 0 {
			addrs, err := netIfs[i].Addrs()
			if err != nil {
				return ""
			}
			for _, addr := range addrs {
				ip, ok := addr.(*net.IPNet)
				if ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
					return ip.IP.String()
				}
			}
		}
	}
	return ""
}

type (
	// node info for rest api query.
	// NodeInfo means one node's information
	NodeInfo struct {
		ID           int64  `json:"id" form:"id"`
		RegTime      string `json:"regtime" form:"regtime"`
		Registered   bool   `json:"registered" form:"registered"`
		Online       bool   `json:"online" form:"online"`
		Trusted      string `json:"trusted" form:"trusted"`
		IsAutoUpdate bool   `json:"isautoupdate" form:"isautoupdate"`
		IPAddress    string `json:"ipaddress" form:"ipaddress"`
	}

	// ArrNodeInfo means struct NodeInfo array
	ArrNodeInfo []NodeInfo
)

func (ni ArrNodeInfo) Len() int           { return len(ni) }
func (ni ArrNodeInfo) Swap(i, j int)      { ni[i], ni[j] = ni[j], ni[i] }
func (ni ArrNodeInfo) Less(i, j int) bool { return ni[i].ID < ni[j].ID }

type (
	// TrustReportInput is used to describe the input of trust report
	TrustReportInput struct {
		ClientID   int64
		Nonce      uint64
		ClientInfo string
	}

	// TaReportInput means ta report information
	TaReportInput struct {
		Uuid     string
		UserData []byte
		WithTcb  bool
	}
)

type (
	// GetRequestPayload means kms request information.
	GetRequestPayload struct {
		TemplateAttribute *kmip.TemplateAttribute
	}

	// GetResponsePayload means kms response information.
	GetResponsePayload struct {
		TemplateAttribute *kmip.TemplateAttribute
	}

	// GetHandler contains get function
	// which gets request and returns response.
	GetHandler struct {
		Get func(ctx context.Context, payload *GetRequestPayload) (*GetResponsePayload, error)
	}
)

// HandleItem handles request payload
// and returns kmip response batch item.
func (h *GetHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload GetRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Get(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}

// Get the hash value of TrustReportIn, as user data of Quote
// Hash returns trustreportinput's hash value.
func (t *TrustReportInput) Hash(algStr string) ([]byte, error) {
	buf := new(bytes.Buffer)
	b64 := make([]byte, 8)
	binary.BigEndian.PutUint64(b64, t.Nonce)
	buf.Write(b64)
	binary.BigEndian.PutUint64(b64, uint64(t.ClientID))
	buf.Write(b64)
	buf.WriteString(t.ClientInfo)
	bHash, err := GetHFromAlg(algStr)
	if err != nil {
		return nil, err
	}
	_, err1 := bHash.Write(buf.Bytes())
	if err1 != nil {
		return nil, err1
	}
	return bHash.Sum(nil), nil
}

type (
	// PCR handle
	// PcrGroups means groups of pcr
	PcrGroups struct {
		Sha1Hash   [PcrMaxNum]hash.Hash
		Sha256Hash [PcrMaxNum]hash.Hash
		SM3Hash    [PcrMaxNum]hash.Hash
		Sha1Pcrs   [PcrMaxNum][]byte
		Sha256Pcrs [PcrMaxNum][]byte
		SM3Pcrs    [PcrMaxNum][]byte
	}
)

// NewPcrGroups returns one new PcrGroups.
func NewPcrGroups() *PcrGroups {
	pcrs := PcrGroups{}
	for i := 0; i < PcrMaxNum; i++ {
		pcrs.Sha1Hash[i] = sha1.New()
		pcrs.Sha256Hash[i] = sha256.New()
		pcrs.SM3Hash[i] = sm3.New()
		pcrs.Sha1Pcrs[i] = make([]byte, Sha1DigestLen)
		pcrs.Sha256Pcrs[i] = make([]byte, Sha256DigestLen)
		pcrs.SM3Pcrs[i] = make([]byte, SM3DigestLen)
	}
	return &pcrs
}

// ExtendSha1 returns Sha1 hash with extending value.
func (pcrs *PcrGroups) ExtendSha1(index int, value []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha1Hash[index]
	_, err := h.Write(pcrs.Sha1Pcrs[index])
	if err != nil {
		return
	}
	_, err1 := h.Write(value)
	if err1 != nil {
		return
	}
	pcrs.Sha1Pcrs[index] = h.Sum(nil)
	h.Reset()
}

// ExtendSha256 returns Sha256 hash with extending value.
func (pcrs *PcrGroups) ExtendSha256(index int, value []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha256Hash[index]
	_, err := h.Write(pcrs.Sha256Pcrs[index])
	if err != nil {
		return
	}
	_, err1 := h.Write(value)
	if err1 != nil {
		return
	}
	pcrs.Sha256Pcrs[index] = h.Sum(nil)
	h.Reset()
}

// ExtendSM3 returns SM3 hash with extending value.
func (pcrs *PcrGroups) ExtendSM3(index int, value []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.SM3Hash[index]
	_, err := h.Write(pcrs.SM3Pcrs[index])
	if err != nil {
		return
	}
	_, err1 := h.Write(value)
	if err1 != nil {
		return
	}
	pcrs.SM3Pcrs[index] = h.Sum(nil)
	h.Reset()
}

// ExtendIMALog modified PcrGroups with value and name according to algStr.
func (pcrs *PcrGroups) ExtendIMALog(index int, value, name []byte, algStr string) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	var h hash.Hash
	switch algStr {
	case Sha1AlgStr:
		h = pcrs.Sha1Hash[index]
	case Sha256AlgStr:
		h = pcrs.Sha256Hash[index]
	case Sm3AlgStr:
		h = pcrs.SM3Hash[index]
	}
	_, err := h.Write(value)
	if err != nil {
		return
	}
	_, err1 := h.Write(name)
	if err1 != nil {
		return
	}
	if len(name) < imaItemNameLenMax+1 {
		_, err2 := h.Write(make([]byte, imaItemNameLenMax+1-len(name)))
		if err2 != nil {
			return
		}
	}
	switch algStr {
	case Sha1AlgStr:
		pcrs.Sha1Pcrs[index] = h.Sum(nil)
	case Sha256AlgStr:
		pcrs.Sha256Pcrs[index] = h.Sum(nil)
	case Sm3AlgStr:
		pcrs.SM3Pcrs[index] = h.Sum(nil)
	}
	h.Reset()
}

// ima-ng doesn't support sha1 alg
func (pcrs *PcrGroups) ExtendIMANGLog(index int, value, name []byte, algStr string) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	var h hash.Hash
	switch algStr {
	case Sha1AlgStr:
		h = pcrs.Sha1Hash[index]
	case Sha256AlgStr:
		h = pcrs.Sha256Hash[index]
	case Sm3AlgStr:
		h = pcrs.SM3Hash[index]
	}
	i := bytes.Index(value, Colon)
	b := bytes.Buffer{}
	b.Write(value[:i+1]) // "sha256:"
	b.WriteByte(0)
	s := make([]byte, hex.DecodedLen(len(value[i+1:])))
	_, err := hex.Decode(s, value[i+1:])
	if err != nil {
		return
	}
	b.Write(s) // binary hash
	sLen := make([]byte, uint32Len)
	binary.LittleEndian.PutUint32(sLen, uint32(b.Len()))
	_, err1 := h.Write(sLen)
	if err1 != nil {
		return
	}
	_, err2 := h.Write(b.Bytes())
	if err2 != nil {
		return
	}
	binary.LittleEndian.PutUint32(sLen, uint32(len(name))+1)
	_, err3 := h.Write(sLen)
	if err3 != nil {
		return
	}
	_, err4 := h.Write(name)
	if err4 != nil {
		return
	}
	_, err5 := h.Write([]byte{0})
	if err5 != nil {
		return
	}
	switch algStr {
	case Sha1AlgStr:
		pcrs.Sha1Pcrs[index] = h.Sum(nil)
	case Sha256AlgStr:
		pcrs.Sha256Pcrs[index] = h.Sum(nil)
	case Sm3AlgStr:
		pcrs.SM3Pcrs[index] = h.Sum(nil)
	}
	h.Reset()
}

// GetHFromAlg returns hash.Hash corresponding to algStr.
func GetHFromAlg(algStr string) (hash.Hash, error) {
	switch algStr {
	case Sha1AlgStr:
		return sha1.New(), nil
	case Sha256AlgStr:
		return sha256.New(), nil
	case Sm3AlgStr:
		return sm3.New(), nil
	default:
		return nil, ErrNotSupportAlg
	}
}

// AggregateSha1 returns the specified pcrs.Sha1Pcrs string.
func (pcrs *PcrGroups) AggregateSha1(from, to int) string {
	if from < 0 || from >= PcrMaxNum {
		return ""
	}
	if to < 0 || to > PcrMaxNum || from > to {
		return ""
	}
	h := sha1.New()
	for i := from; i < to; i++ {
		_, err := h.Write(pcrs.Sha1Pcrs[i])
		if err != nil {
			return ""
		}
	}
	buf := h.Sum(nil)
	return hex.EncodeToString(buf)
}

// AggregateSha256 returns the specified pcrs.Sha256Pcrs string.
func (pcrs *PcrGroups) AggregateSha256(from, to int) string {
	if from < 0 || from >= PcrMaxNum {
		return ""
	}
	if to < 0 || to > PcrMaxNum || from > to {
		return ""
	}
	h := sha256.New()
	for i := from; i < to; i++ {
		_, err := h.Write(pcrs.Sha256Pcrs[i])
		if err != nil {
			return ""
		}
	}
	buf := h.Sum(nil)
	return hex.EncodeToString(buf)
}

// AggregateSM3 returns the specified pcrs.SM3Pcrs string.
func (pcrs *PcrGroups) AggregateSM3(from, to int) string {
	if from < 0 || from >= PcrMaxNum {
		return ""
	}
	if to < 0 || to > PcrMaxNum || from > to {
		return ""
	}
	h := sm3.New()
	for i := from; i < to; i++ {
		h.Write(pcrs.SM3Pcrs[i])
	}
	buf := h.Sum(nil)
	return hex.EncodeToString(buf)
}

type (
	// for generating detail in ManifestItem, defined according to PCG doc
	BIOSManifestItem struct {
		// pcr number
		Pcr uint32
		// bios manifest type, as known as name, corresponding name in the ManifestItem
		BType uint32
		// hash digest
		Digest DigestValues
		// data length
		DataLen uint32
		// store data hex value
		DataHex string
	}

	DigestValues struct {
		// digest count
		Count uint32
		// digest item
		Item []DigestItem
	}

	DigestItem struct {
		// algorithm ID. it is also defined in PCG doc
		AlgID string
		// every digest value
		Item string
	}
)

func readUint32(origin []byte, point *int64) (uint32, error) {
	target := make([]byte, uint32Len)
	end := *point + int64(len(target))
	if *point > int64(len(origin)) || end > int64(len(origin)) {
		return 0, errors.New("end of file")
	}
	copy(target, origin[*point:end])
	bb := bytes.NewBuffer(target)
	var result uint32
	err := binary.Read(bb, binary.LittleEndian, &result)
	if err != nil {
		return 0, err
	}
	*point += int64(len(target))
	return result, nil
}

func readBytes(target []byte, origin []byte, point *int64) ([]byte, error) {
	end := *point + int64(len(target))
	if *point > int64(len(origin)) || end > int64(len(origin)) {
		return nil, errors.New("end of file")
	}
	copy(target, origin[*point:end])
	*point += int64(len(target))
	return target, nil
}

func getSpecID(origin []byte) string {
	result := make([]byte, specLen)
	copy(result, origin[specStart:specEnd])
	return string(bytes.Trim(result, SpaceZero))
}

func getAlgNum(origin []byte) (uint32, error) {
	target := make([]byte, algNumLen)
	copy(target, origin[algNumStart:algNumEnd])
	bb := bytes.NewBuffer(target)
	var result uint32
	err := binary.Read(bb, binary.LittleEndian, &result)
	if err != nil {
		return 0, err
	}
	return result, nil
}

func getAlgAndLenMap(origin []byte, algNum uint32) (map[string]int, error) {
	result := map[string]int{}
	for i := 0; i < int(algNum); i++ {
		algIDBytes := make([]byte, algIDLen)
		newStart := algAndSizeStart + i*(algIDLen+algDigestSizeLen)
		copy(algIDBytes, origin[newStart:newStart+algIDLen])
		algID := hex.EncodeToString(algIDBytes)

		algDigestSizeBytes := make([]byte, algDigestSizeLen)
		copy(algDigestSizeBytes, origin[newStart+algIDLen:newStart+algIDLen+algDigestSizeLen])
		bb := bytes.NewBuffer(algDigestSizeBytes)
		var algDigestSize uint16
		err := binary.Read(bb, binary.LittleEndian, &algDigestSize)
		if err != nil {
			return nil, err
		}
		result[algID] = int(algDigestSize)
	}
	return result, nil
}

func readSHA1BIOSEventLog(origin []byte, point *int64) (*BIOSManifestItem, error) {
	pcr, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	bType, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	digestBytes := make([]byte, Sha1DigestLen)
	digestBytes, err = readBytes(digestBytes, origin, point)
	if err != nil {
		return nil, err
	}
	dataLength, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dataBytes := make([]byte, dataLength)
	dataBytes, err = readBytes(dataBytes, origin, point)
	if err != nil {
		return nil, err
	}

	// real SHA1 BIOS event log in TPM1.2 doesn't have digest count and item. see detail in the doc
	result := &BIOSManifestItem{
		Pcr:   pcr,
		BType: bType,
		Digest: DigestValues{
			Count: 1,
			Item: []DigestItem{
				{
					AlgID: sha1AlgID,
					Item:  hex.EncodeToString(digestBytes),
				},
			},
		},
		DataLen: dataLength,
		DataHex: hex.EncodeToString(dataBytes),
	}
	return result, nil
}

// ReadBIOSEvent2Log gets Pcr, BType and Digest from origin and returns *BIOSManifestItem.
func ReadBIOSEvent2Log(origin []byte, point *int64, algAndLenMap map[string]int) (*BIOSManifestItem, error) {
	pcr, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	bType, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dCount, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}

	dv, err := parseDigestValues(dCount, origin, point, algAndLenMap)
	if err != nil {
		return nil, err
	}
	dataLength, err := readUint32(origin, point)
	if err != nil {
		return nil, err
	}
	dataBytes := make([]byte, dataLength)
	dataBytes, err = readBytes(dataBytes, origin, point)
	if err != nil {
		return nil, err
	}
	result := &BIOSManifestItem{
		Pcr:     pcr,
		BType:   bType,
		Digest:  *dv,
		DataLen: dataLength,
		DataHex: hex.EncodeToString(dataBytes),
	}
	return result, nil
}

func parseDigestValues(cnt uint32, origin []byte, point *int64, algAndLenMap map[string]int) (*DigestValues, error) {
	var err error
	dAlgIDBytes := make([]byte, digestAlgIDLen)
	dv := &DigestValues{Count: cnt}
	for i := 0; i < int(cnt); i++ {
		dAlgIDBytes, err = readBytes(dAlgIDBytes, origin, point)
		if err != nil {
			return nil, err
		}
		algIDStr := hex.EncodeToString(dAlgIDBytes)
		if dLen, ok := algAndLenMap[algIDStr]; ok {
			dBytes := make([]byte, dLen)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, DigestItem{
				AlgID: algIDStr,
				Item:  hex.EncodeToString(dBytes),
			})
		} else {
			return nil, ErrBiosLogFormatWrong
		}
	}
	return dv, nil
}

// GetHashValue determines if alg and BIOSManifestItem's Digest.Item.AlgID are the same,
// if they are, return corresponding hash value,
// otherwise return naStr.
func GetHashValue(alg string, evt *BIOSManifestItem) string {
	algMap := map[string]string{
		Sha1AlgStr:   sha1AlgID,
		Sha256AlgStr: sha256AlgID,
		Sm3AlgStr:    sm3AlgID,
	}
	if algID, ok := algMap[alg]; ok {
		for _, hv := range evt.Digest.Item {
			if hv.AlgID == algID {
				return hv.Item
			}
		}
	}
	return naStr
}

// TransformBIOSBinLogToTxt transforms the bios binary log to text.
// The text log has the following fields, separated by space:
//
// column 1: index
// column 2: pcr index
// column 3: BType
// column 4: sha1 hash text
// column 5: sha256 hash text
// column 6: sm3 hash text
// column 7: data hex string
//
// Notes:
// 1) if sha1/sha256/sm3 doesn't exist, use "N/A" string to place.
// 2) column7 data string is hex string, needs to explain later...
func TransformBIOSBinLogToTxt(bin []byte) ([]byte, error) {
	var point int64 = 0
	var buf bytes.Buffer
	_, err := readSHA1BIOSEventLog(bin, &point)
	if err != nil {
		return nil, err
	}
	SpecID := getSpecID(bin)
	// if SpecID is "Spec ID Event03", this is a event2 log bytes stream
	if strings.Contains(SpecID, event2SpecID) {
		algNum, err := getAlgNum(bin)
		if err != nil {
			return nil, err
		}
		algAndLenMap, err := getAlgAndLenMap(bin, algNum)
		if err != nil {
			return nil, err
		}
		writeBuf(&buf, bin, &point, algAndLenMap)
	}
	return buf.Bytes(), nil
}

func writeBuf(buf *bytes.Buffer, bin []byte, point *int64, algAndLenMap map[string]int) {
	for i := 0; ; i++ {
		event2Log, err := ReadBIOSEvent2Log(bin, point, algAndLenMap)
		if err != nil {
			break
		}
		buf.WriteString(fmt.Sprintf("%02d %02d ", i,
			event2Log.Pcr))
		buf.WriteString(fmt.Sprint(fmt.Sprintf("%x", event2Log.BType), "-", i, " "))
		buf.WriteString(GetHashValue(Sha1AlgStr, event2Log))
		strNext := GetHashValue(Sha256AlgStr, event2Log)
		if strNext == naStr {
			buf.WriteString(" " + naStr)
		} else {
			buf.WriteString(" " + Sha256AlgStr + ":")
			buf.WriteString(strNext)
		}
		strNext = GetHashValue(Sm3AlgStr, event2Log)
		if strNext == naStr {
			buf.WriteString(" " + naStr)
		} else {
			buf.WriteString(" " + Sm3AlgStr + ":")
			buf.WriteString(strNext)
		}
		buf.WriteString(fmt.Sprintf(" %s\n", event2Log.DataHex))
	}
}

// ExtendPCRWithBIOSTxtLog extends the bios log into pcrs.
// it use column nums of one line to get type of bios log.
func ExtendPCRWithBIOSTxtLog(pcrs *PcrGroups, biosTxtLog []byte) {
	s1 := make([]byte, Sha1DigestLen)
	s2 := make([]byte, Sha256DigestLen)
	s3 := make([]byte, SM3DigestLen)
	lines := bytes.Split(biosTxtLog, NewLine)
	for _, ln := range lines {
		words := bytes.Split(ln, Space)
		if len(words) == BiosLogItemNum {
			n, err := strconv.Atoi(string(words[1]))
			if err != nil {
				return
			}
			_, err1 := hex.Decode(s1, words[3])
			if err1 != nil {
				return
			}
			pcrs.ExtendSha1(n, s1)
			if string(words[4]) != naStr {
				i := bytes.Index(words[4], Colon)
				_, err := hex.Decode(s2, words[4][i+1:])
				if err != nil {
					return
				}
				pcrs.ExtendSha256(n, s2)
			}
		}
		if len(words) == SM3BiosLogItemNum {
			n, err := strconv.Atoi(string(words[1]))
			if err != nil {
				return
			}
			_, err1 := hex.Decode(s1, words[3])
			if err1 != nil {
				return
			}
			pcrs.ExtendSha1(n, s1)
			if string(words[4]) != naStr {
				i := bytes.Index(words[4], Colon)
				_, err := hex.Decode(s2, words[4][i+1:])
				if err != nil {
					return
				}
				pcrs.ExtendSha256(n, s2)
			}
			if string(words[5]) != naStr {
				j := bytes.Index(words[5], Colon)
				_, err := hex.Decode(s3, words[5][j+1:])
				if err != nil {
					return
				}
				pcrs.ExtendSM3(n, s3)
			}
		}
	}
}

func parseIMALine(line []byte) (int, [][]byte, error) {
	ln := bytes.Trim(line, string(Space))
	if len(ln) == 0 {
		return 0, nil, nil
	}
	words := bytes.Split(ln, Space)
	if len(words) < ImaLogItemNum {
		return 0, nil, ErrImaLogFormatWrong
	}
	if len(words) > ImaLogItemNum {
		words[4] = bytes.Join(words[4:], Space)
	}
	index, err := strconv.Atoi(string(words[0])) // PcrIndex
	if err != nil {
		return 0, nil, err
	}
	if index < 0 || index >= PcrMaxNum {
		return 0, nil, ErrPcrIndexWrong
	}
	return index, words, nil
}

func handleIMAWordsByTag(words [][]byte, t1 []byte, s1 []byte, pcrs *PcrGroups, algStr string, index int) error {
	switch string(words[2]) {
	case StrIma:
		_, err := hex.Decode(s1, words[3]) // FiledataHash
		if err != nil {
			return ErrImaLogFormatWrong
		}
		pcrs.ExtendIMALog(index, s1, words[4], algStr)
		if !bytes.Equal(t1, pcrs.Sha1Pcrs[index]) {
			return ErrValidateIMAFail
		}
	case StrImaNg:
		pcrs.ExtendIMANGLog(index, words[3], words[4], algStr)
		if !bytes.Equal(t1, pcrs.Sha256Pcrs[index]) {
			return ErrValidateIMAFail
		}
	}
	return nil
}

func handleIMALine(pcrs *PcrGroups, line []byte, algStr string) (bool, error) {
	var t1 []byte
	var s1 []byte
	if dLen, ok := SupportAlgAndLenMap[algStr]; ok {
		t1 = make([]byte, dLen)
		s1 = make([]byte, dLen)
	} else {
		return false, ErrNotSupportAlg
	}

	index, words, err := parseIMALine(line)
	if err != nil {
		return false, err
	}
	if len(words) == ImaLogItemNum {
		_, err = hex.Decode(t1, words[1]) // TemplateHash to verify
		if err != nil {
			return false, ErrImaLogFormatWrong
		}
		err = handleIMAWordsByTag(words, t1, s1, pcrs, algStr, index)
	}
	return true, nil
}

// ExtendPCRWithIMALog first verifies the bios aggregate, then extends ima
// logs into pcr and verifies them one by one.
func ExtendPCRWithIMALog(pcrs *PcrGroups, imaLog []byte, algStr string) (bool, error) {
	var aggr string
	switch algStr {
	case Sha1AlgStr:
		aggr = pcrs.AggregateSha1(0, 8)
	case Sha256AlgStr:
		aggr = pcrs.AggregateSha256(0, 10)
	case Sm3AlgStr:
		aggr = pcrs.AggregateSM3(0, 10)
	default:
		return false, ErrNotSupportAlg
	}

	lines := bytes.Split(imaLog, NewLine)
	ws := bytes.Split(lines[0], Space)
	if len(ws) != ImaLogItemNum {
		return false, ErrImaLogFormatWrong
	}
	aggrNameAndHash := bytes.Split(ws[3], Colon)
	var sAggr []byte
	if len(aggrNameAndHash) > 1 {
		sAlgName := aggrNameAndHash[0]
		if string(sAlgName) != algStr {
			return false, ErrNotMatchAlg
		}
		sAggr = aggrNameAndHash[1]
	} else {
		sAggr = aggrNameAndHash[0]
	}
	if !bytes.Equal(sAggr, []byte(aggr)) {
		return false, ErrBiosAggregateFail
	}
	for _, line := range lines {
		ret, err := handleIMALine(pcrs, line, algStr)
		if !ret {
			return ret, err
		}
	}
	return true, nil
}

/*
		AddPcr8And9FromPcrMap is called because of this commit in openEuler 2203 :

		commit 20c59ce010f84300f6c655d32db2610d3433f85c
	    ima: extend boot_aggregate with kernel measurements
	    Registers 8-9 are used to store measurements of the kernel and its
	    command line (e.g., grub2 bootloader with tpm module enabled). IMA
	    should include them in the boot aggregate. Registers 8-9 should be
	    only included in non-SHA1 digests to avoid ambiguity.
*/
func AddPcr8And9FromPcrMap(pcrs *PcrGroups, pcrMap map[int]string, algStr string) error {
	if algStr == Sha1AlgStr {
		return nil
	}
	for i := 8; i <= 9; i++ {
		pcrValueBytes, err := hex.DecodeString(pcrMap[i])
		if err != nil {
			return err
		}
		switch algStr {
		case Sha256AlgStr:
			pcrs.Sha256Pcrs[i] = pcrValueBytes
		case Sm3AlgStr:
			pcrs.SM3Pcrs[i] = pcrValueBytes
		default:
			return ErrNotSupportAlg
		}
	}
	return nil
}

func parseFile(name string) [][][]byte {
	content, err := ioutil.ReadFile(name)
	if err != nil {
		return nil
	}
	res := make([][][]byte, 0, 20)
	lines := bytes.Split(content, NewLine)
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			words := bytes.Split(line, Space)
			res = append(res, words)
		}
	}
	return res
}

func compareImaToBaseInfo(line [][]byte, baseInfo [][][]byte, isMatched []bool) bool {
	if len(line) < 5 {
		return false
	}
	for i := 0; i < len(baseInfo); i++ {
		if len(baseInfo[i]) < 3 {
			continue
		}
		if !isMatched[i] &&
			bytes.Equal(line[4], baseInfo[i][2]) && // compare filename
			bytes.Equal(line[3], baseInfo[i][1]) { // compare hash value
			isMatched[i] = true
			return true
		}
	}
	return false
}

func areAllMatched(flag []bool) bool {
	for i := 0; i < len(flag); i++ {
		if !flag[i] {
			return false
		}
	}
	return true
}

// CompareIMALog compares the base file and IMA log of trust report, return trust or not.
// Base file has the following format per line:
//
// "sha1 value" + space + "sha256 value" + "/path/to/filename"
//
// IMA log report has the following format per line:
//
// "PCR value" + space + "sha1" + space + "type string" + "sha1/sha256" + "/path/to/filename"
func CompareIMALog(baseFile string, imaLog string) bool {
	base := parseFile(baseFile)
	if base == nil {
		return false
	}
	ima := parseFile(imaLog)
	if ima == nil {
		return false
	}
	isMatched := make([]bool, len(base)) // record whether the base is matched or not
	for _, line := range ima {
		if compareImaToBaseInfo(line, base, isMatched) &&
			areAllMatched(isMatched) {
			return true
		}
	}
	return false
}
