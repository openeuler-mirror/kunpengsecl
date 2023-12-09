/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-05-01
Description: invoke attester lib and get info from qapi
*/

package attestertools

/*
#cgo CFLAGS: -I../../../tverlib/verifier
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/verifier -lteeverifier
#include "teeverifier.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
)

const (
	// default config
	attesterVersion = "version 1.0.0"
	// version output
	lflagVersion = "version"
	sflagVersion = "V"
	helpVersion  = "show version number and quit"
	// server listen ip:port
	lflagServer = "server"
	sflagServer = "S"
	helpServer  = "specify the IP address of the port to be connected"
	// basevalue file path set
	lflagBasevalue = "basevalue"
	sflagBasevalue = "B"
	helpBasevalue  = "set the file path of basevalue to be read"
	// measure policy set
	lflagMeasure = "mspolicy"
	sflagMeasure = "M"
	helpMeasure  = "set a measurement policy to be used"
	// QTA's uuid set
	lflagUuid = "uuid"
	sflagUuid = "U"
	helpUuid  = "specify the QTA to be verifier"
	// test mode with a fixed nonce value ********* based on simulation for qcalib
	lflagTest = "test"
	sflagTest = "T"
	helpTest  = "set a fixed nonce value for test"
	// container info
	sflagVirtGuestId   = "id"
	helpVirtGuestId    = "specify the virtual guest id where ta running"
	sflagVirtGuestType = "type"
	helpVirtGuestType  = "specify the virtual guest type where ta running"

	// app name
	appAttester = "attester"
	// ConfName means config file name
	ConfName = "config"
	// ConfExt means config file name suffix
	ConfExt = "yaml"
	// attester config path
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/qca"
	strSysConf   = "/etc/attestation/ras"
	// attester config key
	// server means attesterconfig server
	server = "attesterconfig.server"
	// basevalue means attesterconfig basevalue
	basevalue = "attesterconfig.basevalue"
	// mspolicy means attesterconfig mspolicy
	mspolicy = "attesterconfig.mspolicy"
	// uuid means attesterconfig uuid
	taUuid           = "attesterconfig.uuid"
	virtGuestIdKey   = "attesterconfig.virtualguest.id"
	virtGuestTypeKey = "attesterconfig.virtualguest.type"

	ATTEST_RET_SUCCESS    = 0
	ATTEST_RET_NONCE_FAIL = -1
	ATTEST_RET_SIGN_FAIL  = -2
	ATTEST_RET_HASH_FAIL  = -3
	ATTEST_RET_OTHER_FAIL = -4

	DOCKER_ID_LEN = 64
	KVM_UUID_LEN  = 36
)

type (
	trustApp struct {
		ctx           context.Context
		uuid          []byte
		usrdata       []byte
		report        []byte
		withtcb       bool
		virtGuestId   string
		virtGuestType string
	}
	attesterConfig struct {
		server        string
		basevalue     string
		mspolicy      int
		uuid          string
		virtGuestId   string
		virtGuestType string
	}
)

var (
	testmode bool      = false
	test_ta  *trustApp = &trustApp{
		ctx:           context.Background(),
		uuid:          []byte{},
		usrdata:       []byte{},
		report:        []byte{},
		withtcb:       false,
		virtGuestId:   "",
		virtGuestType: "",
	}
	verify_result int = 1
	defaultPaths      = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	// versionFlag means version flag
	versionFlag *bool = nil
	// testFlag means test flag
	testFlag *bool = nil

	// attester config, use in attestertools package
	attesterConf *attesterConfig = &attesterConfig{}
)

// InitFlags inits the server command flags. default value from config.yaml file
func InitFlags() {
	log.Print("Init attester flags......")
	versionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	testFlag = pflag.BoolP(lflagTest, sflagTest, false, helpTest)

	pflag.StringVarP(&attesterConf.server, lflagServer, sflagServer, attesterConf.server, helpServer)
	pflag.StringVarP(&attesterConf.basevalue, lflagBasevalue, sflagBasevalue, attesterConf.basevalue, helpBasevalue)
	pflag.IntVarP(&attesterConf.mspolicy, lflagMeasure, sflagMeasure, attesterConf.mspolicy, helpMeasure)
	pflag.StringVarP(&attesterConf.uuid, lflagUuid, sflagUuid, attesterConf.uuid, helpUuid)
	pflag.StringVar(&attesterConf.virtGuestId, sflagVirtGuestId, attesterConf.virtGuestId, helpVirtGuestId)
	pflag.StringVar(&attesterConf.virtGuestType, sflagVirtGuestType, attesterConf.virtGuestType, helpVirtGuestType)
	pflag.Parse()
}

// LoadConfigs searches and loads config from config.yaml file.
func LoadConfigs() {
	log.Print("Load attester Configs......")

	viper.SetConfigName(ConfName)
	viper.SetConfigType(ConfExt)
	for _, s := range defaultPaths {
		viper.AddConfigPath(s)
	}
	err := viper.ReadInConfig()
	if err != nil {
		log.Printf("Read config file failed! %v", err)
		return
	}
	attesterConf.server = viper.GetString(server)
	attesterConf.basevalue = viper.GetString(basevalue)
	attesterConf.mspolicy = viper.GetInt(mspolicy)
	attesterConf.uuid = viper.GetString(taUuid)
	attesterConf.virtGuestId = viper.GetString(virtGuestIdKey)
	attesterConf.virtGuestType = viper.GetString(virtGuestTypeKey)
}

// HandleFlags handles the command flags.
func HandleFlags() {
	log.Println("Handle attester flags......")
	if versionFlag != nil && *versionFlag {
		log.Printf("TEE Remote Attester: %s\n", attesterVersion)
		os.Exit(0)
	}

	log.Printf("Attester config: %v\n", attesterConf)

	if testFlag != nil && *testFlag {
		testmode = true
		// var s_nonce string = "challenge" // 换成获取到的nonce（不是string，要先base64解码）
		// nonce := []byte(s_nonce)
		var s_nonce string = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ent8fX5_gA"
		nonce, err := base64.RawURLEncoding.DecodeString(s_nonce)
		if err != nil {
			log.Printf("nonce base64 decode error: %v\n", err)
			os.Exit(0)
		}
		test_ta.usrdata = nonce
	}
}

// StartAttester initializes the parameters of TA and verifies ta report.
func StartAttester() {
	log.Print("Start Attester......")
	test_ta, err := iniTAParameter(test_ta, testmode)
	if err != nil {
		log.Printf("Init TA parameter failed! %v", err)
		return
	}
	test_ta.report = getReport(test_ta)
	verify_result = tee_verify(test_ta, attesterConf.mspolicy, attesterConf.basevalue)
	switch verify_result {
	case ATTEST_RET_SUCCESS:
		log.Print("tee verify succeeded!")
	case ATTEST_RET_NONCE_FAIL:
		log.Print("tee verify nonce failed!")
	case ATTEST_RET_SIGN_FAIL:
		log.Print("tee verify signature failed!")
	case ATTEST_RET_HASH_FAIL:
		log.Print("tee verify hash failed!")
	default:
		log.Print("tee verify get other error!")
	}

	log.Print("Stop Attester......")
}

func checkVirtGuestInfo(id, ctype string) error {
	// no container info input is valid
	if id == "" && ctype == "" {
		return nil
	}

	if id == "" || ctype == "" {
		return fmt.Errorf("id or type lacked")
	}
	switch strings.ToLower(ctype) {
	case "docker":
		if len(id) != DOCKER_ID_LEN {
			return fmt.Errorf("invalid id length %d", len(id))
		}
	case "kvm":
		if len(id) != KVM_UUID_LEN {
			return fmt.Errorf("invalid uuid length %d", len(id))
		}
	default:
		return fmt.Errorf("not supported container type")
	}
	return nil
}

// iniTAParameter initializes the parameters of TA
func iniTAParameter(ta *trustApp, m bool) (*trustApp, error) {
	id, err := uuid.Parse(attesterConf.uuid)
	if err != nil {
		return nil, err
	}
	ta.uuid, err = id.MarshalBinary()
	if err != nil {
		return nil, err
	}
	// create nonce value to defend against replay attacks
	if !m {
		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		if err != nil {
			return nil, err
		}
		ta.usrdata = nonce
	}

	err = checkVirtGuestInfo(attesterConf.virtGuestId, attesterConf.virtGuestType)
	if err != nil {
		return nil, err
	}
	ta.virtGuestId = strings.ToLower(attesterConf.virtGuestId)
	ta.virtGuestType = strings.ToLower(attesterConf.virtGuestType)
	return ta, nil
}

// remote invoke qca api to get the TA's info
func getReport(ta *trustApp) []byte {
	if ta == nil {
		log.Printf("invalid input ta")
		return nil
	}

	var info *qapi.GetReportRequest_VirtualGuestInfo
	if ta.virtGuestId != "" && ta.virtGuestType != "" {
		info = &qapi.GetReportRequest_VirtualGuestInfo{
			Id:   ta.virtGuestId,
			Type: ta.virtGuestType,
		}
	}

	reqID := qapi.GetReportRequest{
		Uuid:    ta.uuid,
		Nonce:   ta.usrdata,
		WithTcb: ta.withtcb,
		Info:    info,
	}

	log.Printf("Virtual guest info: %v\n", info)

	rpyID, err := qapi.DoGetTeeReport(attesterConf.server, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, error: %v", err)
		return nil
	}
	log.Print("Get TA report succeeded!")
	ta.report = rpyID.GetTeeReport()
	return ta.report
}

func adaptkvm(ta *trustApp) error {
	if ta == nil || ta.virtGuestType != "kvm" {
		return nil
	}

	// convert uuid to 64 id and type to docker
	ta.virtGuestType = "docker"
	uuid, err := uuid.Parse(ta.virtGuestId)
	if err != nil {
		return fmt.Errorf("uuid is invalid, %v", err)
	}

	id16 := uuid[:]
	id32 := append(id16, id16...)
	ta.virtGuestId = hex.EncodeToString(id32)
	return nil
}

// invoke verifier lib to verify
func tee_verify(ta *trustApp, mtype int, bv string) int {
	// in report, type is docker, id is 64id
	if err := adaptkvm(ta); err != nil {
		log.Printf("adapt kvm info failed, %v\n", err)
		return ATTEST_RET_OTHER_FAIL
	}
	// construct C data_buf
	var crep C.buffer_data
	crepByte := C.CBytes(ta.report)
	defer C.free(crepByte)
	crep.buf, crep.size = (*C.uchar)(crepByte), C.__uint32_t(len(ta.report))

	// construct C nonce
	var cnonce C.buffer_data
	cnonByte := C.CBytes(ta.usrdata)
	defer C.free(cnonByte)
	cnonce.buf, cnonce.size = (*C.uchar)(cnonByte), C.__uint32_t(len(ta.usrdata))

	// construct C info
	var cinfo *C.container_info = nil
	if ta.virtGuestId != "" && ta.virtGuestType != "" {
		var tmpInfo C.container_info
		cid := C.CString(ta.virtGuestId)
		defer C.free(unsafe.Pointer(cid))
		ctype := C.CString(ta.virtGuestType)
		defer C.free(unsafe.Pointer(ctype))
		tmpInfo.id.buf, tmpInfo.id.size = (*C.uchar)(cid), C.__uint32_t(len(ta.virtGuestId))
		tmpInfo._type.buf, tmpInfo._type.size = (*C.uchar)(ctype), C.__uint32_t(len(ta.virtGuestType))
		cinfo = &tmpInfo
	}

	// construct C filename
	cbv := C.CString(bv)
	defer C.free(unsafe.Pointer(cbv))

	result := C.tee_verify_report(&crep, &cnonce, cinfo, C.int(mtype), cbv)
	return int(result)
}
