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
	Sha1DigestLen   = 20
	Sha256DigestLen = 32
	Sha1AlgStr      = "sha1"
	Sha256AlgStr    = "sha256"
	PcrMaxNum       = 24
)

// definitions for BIOS/IMA log parse used only in this package.
const (
	uint32Len         = 4
	digestAlgIDLen    = 2
	sha1AlgID         = "0400"
	sha256AlgID       = "0b00"
	event2SpecID      = "Spec ID Event03"
	specLen           = 16
	specStart         = 32
	specEnd           = 48
	imaLogItemNum     = 5
	biosLogItemNum    = 6
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
	}

	// Manifest stores the pcr/bios/ima log part of trust report.
	Manifest struct {
		Key   string // pcr/bios/ima
		Value []byte // log file content
	}

	// ClientRow stores one record of client basic information
	// in database table `client`.
	ClientRow struct {
		ID      int64
		RegTime time.Time
		Deleted bool
		Info    string
		IKCert  string
	}

	// ReportRow stores one record of trust report information
	// in database table `report`.
	ReportRow struct {
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

	// BaseRow stores one record of the base information in database
	// table `base`, which is specified by customer and will be used
	// to verify trust report.
	BaseRow struct {
		ClientID   int64
		CreateTime time.Time
		Name       string
		Pcr        string
		Bios       string
		Ima        string
		Enabled    bool
		Verified   bool
		Trusted    bool
	}
)

var (
	//
	NewLine   = []byte("\n")
	Space     = []byte(" ")
	Colon     = []byte(":")
	SpaceZero = " \x00"

	//
	ErrPcrIndexWrong     = errors.New("pcr index wrong")
	ErrImaLogFormatWrong = errors.New("ima log format wrong")
	ErrBiosAggregateFail = errors.New("bios aggregate not match")
	ErrValidateIMAFail   = errors.New("validate ima log fail")

	// client database handle errors
	ErrParameterWrong    = errors.New("parameter is wrong")
	ErrAlgorithmWrong    = errors.New("report algorithm is wrong")
	ErrConnectFailed     = errors.New("create connection failed")
	ErrDoesnotRegistered = errors.New("client does not registered")
	ErrAlreadyRegistered = errors.New("client already registered")
	ErrIKCertNull        = errors.New("client ik cert null")
	ErrNonceNotMatch     = errors.New("report nonce not match")
	ErrPCRNotMatch       = errors.New("report pcr not match")
)

// GetIP returns the host ipv4 address
func GetIP() string {
	netIfs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for i := 0; i < len(netIfs); i++ {
		if (netIfs[i].Flags & net.FlagUp) != 0 {
			addrs, _ := netIfs[i].Addrs()
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
	TrustReportInput struct {
		ClientID   int64
		Nonce      uint64
		ClientInfo string
	}
)

// Get the hash value of TrustReportIn, as user data of Quote
func (t *TrustReportInput) Hash() []byte {
	buf := new(bytes.Buffer)
	b64 := make([]byte, 8)
	binary.BigEndian.PutUint64(b64, t.Nonce)
	buf.Write(b64)
	binary.BigEndian.PutUint64(b64, uint64(t.ClientID))
	buf.Write(b64)
	buf.WriteString(t.ClientInfo)
	bHash := sha256.New()
	bHash.Write(buf.Bytes())
	return bHash.Sum(nil)
}

type (
	// PCR handle
	PcrGroups struct {
		Sha1Hash   [PcrMaxNum]hash.Hash
		Sha256Hash [PcrMaxNum]hash.Hash
		Sha1Pcrs   [PcrMaxNum][]byte
		Sha256Pcrs [PcrMaxNum][]byte
	}
)

func NewPcrGroups() *PcrGroups {
	pcrs := PcrGroups{}
	for i := 0; i < PcrMaxNum; i++ {
		pcrs.Sha1Hash[i] = sha1.New()
		pcrs.Sha256Hash[i] = sha256.New()
		pcrs.Sha1Pcrs[i] = make([]byte, Sha1DigestLen)
		pcrs.Sha256Pcrs[i] = make([]byte, Sha256DigestLen)
	}
	return &pcrs
}

func (pcrs *PcrGroups) ExtendSha1(index int, value []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha1Hash[index]
	h.Write(pcrs.Sha1Pcrs[index])
	h.Write(value)
	pcrs.Sha1Pcrs[index] = h.Sum(nil)
	h.Reset()
}

func (pcrs *PcrGroups) ExtendSha256(index int, value []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha256Hash[index]
	h.Write(pcrs.Sha256Pcrs[index])
	h.Write(value)
	pcrs.Sha256Pcrs[index] = h.Sum(nil)
	h.Reset()
}

func (pcrs *PcrGroups) ExtendIMALog(index int, value, name []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha1Hash[index]
	h.Write(value)
	h.Write(name)
	if len(name) < imaItemNameLenMax+1 {
		h.Write(make([]byte, imaItemNameLenMax+1-len(name)))
	}
	pcrs.Sha1Pcrs[index] = h.Sum(nil)
	h.Reset()
}

func (pcrs *PcrGroups) ExtendIMANGLog(index int, value, name []byte) {
	if index < 0 || index >= PcrMaxNum {
		return
	}
	h := pcrs.Sha256Hash[index]
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
	h.Write(sLen)
	h.Write(b.Bytes())
	binary.LittleEndian.PutUint32(sLen, uint32(len(name))+1)
	h.Write(sLen)
	h.Write(name)
	h.Write([]byte{0})
	pcrs.Sha256Pcrs[index] = h.Sum(nil)
	h.Reset()
}

func (pcrs *PcrGroups) AggregateSha1(from, to int) string {
	if from < 0 || from >= PcrMaxNum {
		return ""
	}
	if to < 0 || to >= PcrMaxNum || from > to {
		return ""
	}
	h := sha1.New()
	for i := from; i < to; i++ {
		h.Write(pcrs.Sha1Pcrs[i])
	}
	buf := h.Sum(nil)
	return hex.EncodeToString(buf)
}

func (pcrs *PcrGroups) AggregateSha256(from, to int) string {
	if from < 0 || from >= PcrMaxNum {
		return ""
	}
	if to < 0 || to >= PcrMaxNum || from > to {
		return ""
	}
	h := sha256.New()
	for i := from; i < to; i++ {
		h.Write(pcrs.Sha256Pcrs[i])
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

func readBIOSEvent2Log(origin []byte, point *int64) (*BIOSManifestItem, error) {
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
	dv, err := parseDigestValues(dCount, origin, point)
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

func parseDigestValues(cnt uint32, origin []byte, point *int64) (*DigestValues, error) {
	var err error
	dAlgIDBytes := make([]byte, digestAlgIDLen)
	dv := &DigestValues{Count: cnt}
	for i := 0; i < int(cnt); i++ {
		dAlgIDBytes, err = readBytes(dAlgIDBytes, origin, point)
		if err != nil {
			return nil, err
		}
		algIDStr := hex.EncodeToString(dAlgIDBytes)
		if algIDStr == sha1AlgID {
			dBytes := make([]byte, Sha1DigestLen)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, DigestItem{
				AlgID: sha1AlgID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
		if algIDStr == sha256AlgID {
			dBytes := make([]byte, Sha256DigestLen)
			dBytes, err = readBytes(dBytes, origin, point)
			if err != nil {
				return nil, err
			}
			dv.Item = append(dv.Item, DigestItem{
				AlgID: sha256AlgID,
				Item:  hex.EncodeToString(dBytes),
			})
		}
	}
	return dv, nil
}

func getHashValue(alg string, evt *BIOSManifestItem) string {
	algMap := map[string]string{
		Sha1AlgStr:   sha1AlgID,
		Sha256AlgStr: sha256AlgID,
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
//   column 1: index
//	 column 2: pcr index
// 	 column 3: BType
//	 column 4: sha1 hash text
//	 column 5: sha256 hash text
//	 column 6: data hex string
// Notes:
// 1) if sha1/sha256 doesn't exist, use "N/A" string to place.
// 2) column6 data string is hex string, needs to explain later...
func TransformBIOSBinLogToTxt(bin []byte) ([]byte, error) {
	var point int64 = 0
	var buf bytes.Buffer
	_, err := readSHA1BIOSEventLog(bin, &point)
	if err != nil {
		return []byte{}, err
	}
	SpecID := getSpecID(bin)
	// if SpecID is "Spec ID Event03", this is a event2 log bytes stream
	if strings.Contains(SpecID, event2SpecID) {
		for i := 0; ; i++ {
			event2Log, err := readBIOSEvent2Log(bin, &point)
			if err != nil {
				break
			}
			buf.WriteString(fmt.Sprintf("%02d %02d %08X ", i,
				event2Log.Pcr, event2Log.BType))
			buf.WriteString(getHashValue(Sha1AlgStr, event2Log))
			buf.WriteString(" sha256:")
			buf.WriteString(getHashValue(Sha256AlgStr, event2Log))
			buf.WriteString(fmt.Sprintf(" %s\n", event2Log.DataHex))
		}
	}
	return buf.Bytes(), nil
}

// ExtendPCRWithBIOSTxtLog extends the bios log into pcrs.
func ExtendPCRWithBIOSTxtLog(pcrs *PcrGroups, biosTxtLog []byte) {
	s1 := make([]byte, Sha1DigestLen)
	s2 := make([]byte, Sha256DigestLen)
	lines := bytes.Split(biosTxtLog, NewLine)
	for _, ln := range lines {
		words := bytes.Split(ln, Space)
		if len(words) == biosLogItemNum {
			n, _ := strconv.Atoi(string(words[1]))
			hex.Decode(s1, words[3])
			pcrs.ExtendSha1(n, s1)
			i := bytes.Index(words[4], Colon)
			hex.Decode(s2, words[4][i+1:])
			pcrs.ExtendSha256(n, s2)
		}
	}
}

func parseIMALine(line []byte) (int, [][]byte, error) {
	ln := bytes.Trim(line, string(Space))
	if len(ln) == 0 {
		return 0, nil, nil
	}
	words := bytes.Split(ln, Space)
	if len(words) < imaLogItemNum {
		return 0, nil, ErrImaLogFormatWrong
	}
	if len(words) > imaLogItemNum {
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

// ExtendPCRWithIMALog first verifies the bios aggregate, then extends ima
// logs into pcr and verifies them one by one.
// TODO: needs to test sha1/sha256/ima/ima-ng all cases, now just test ima/sha1.
func ExtendPCRWithIMALog(pcrs *PcrGroups, imaLog []byte) (bool, error) {
	aggr := pcrs.AggregateSha1(0, 8)
	lines := bytes.Split(imaLog, NewLine)
	ws := bytes.Split(lines[0], Space)
	if len(ws) != imaLogItemNum {
		return false, ErrImaLogFormatWrong
	}
	if !bytes.Equal(ws[3], []byte(aggr)) {
		return false, ErrBiosAggregateFail
	}
	t1 := make([]byte, Sha1DigestLen)
	s1 := make([]byte, Sha1DigestLen)
	for _, line := range lines {
		index, words, err := parseIMALine(line)
		if err != nil {
			return false, err
		}
		if len(words) == imaLogItemNum {
			_, err = hex.Decode(t1, words[1]) // TemplateHash to verify
			if err != nil {
				return false, ErrImaLogFormatWrong
			}
			switch string(words[2]) {
			case StrIma:
				_, err = hex.Decode(s1, words[3]) // FiledataHash
				if err != nil {
					return false, ErrImaLogFormatWrong
				}
				pcrs.ExtendIMALog(index, s1, words[4])
				if !bytes.Equal(t1, pcrs.Sha1Pcrs[index]) {
					return false, ErrValidateIMAFail
				}
			case StrImaNg:
				pcrs.ExtendIMANGLog(index, words[3], words[4])
				if !bytes.Equal(t1, pcrs.Sha256Pcrs[index]) {
					return false, ErrValidateIMAFail
				}
			}
		}
	}
	return true, nil
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
		if !isMatched[i] {
			if bytes.Equal(line[4], baseInfo[i][2]) && // compare filename
				bytes.Equal(line[3], baseInfo[i][1]) { // compare hash value
				isMatched[i] = true
				return true
			}
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

// CompareIMALog compares the base file and IMA log of trust report, reture trust or not.
// Base file has the following format per line:
//	 "sha1 value" + space + "sha256 value" + "/path/to/filename"
// IMA log report has the following format per line:
// 	 "PCR value" + space + "sha1" + space + "type string" + "sha1/sha256" + "/path/to/filename"
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
		if compareImaToBaseInfo(line, base, isMatched) {
			//fmt.Printf("compare ok at %d: %s\n", i, line)
			if areAllMatched(isMatched) {
				//fmt.Printf("end=%d\n", i)
				return true
			}
		}
	}
	return false
}
