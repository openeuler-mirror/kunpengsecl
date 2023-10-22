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
	"fmt"
	"log"
	"os"
	"strings"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
	sflagConId   = "id"
	helpConId    = "specify the container id where ta running"
	sflagConType = "type"
	helpConType  = "specify the container type where ta running"

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
	// Server means attesterconfig server
	Server = "attesterconfig.server"
	// Basevalue means attesterconfig basevalue
	Basevalue = "attesterconfig.basevalue"
	// Mspolicy means attesterconfig mspolicy
	Mspolicy = "attesterconfig.mspolicy"
	// Uuid means attesterconfig uuid
	Uuid       = "attesterconfig.uuid"
	ConIdKey   = "attesterconfig.container.id"
	ConTypeKey = "attesterconfig.container.type"
)

type (
	trustApp struct {
		ctx     context.Context
		uuid    []byte
		usrdata []byte
		report  []byte
		withtcb bool
		conId   string
		conType string
	}
	attesterConfig struct {
		server    string
		basevalue string
		mspolicy  int
		uuid      string
		conId     string
		conType   string
	}
)

var (
	testmode bool      = false
	test_ta  *trustApp = &trustApp{
		ctx:     context.Background(),
		uuid:    []byte{},
		usrdata: []byte{},
		report:  []byte{},
		withtcb: false,
		conId:   "",
		conType: "",
	}
	verify_result int = 1
	defaultPaths      = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	// VersionFlag means version flag
	VersionFlag *bool = nil
	// ServerFlag means server flag
	ServerFlag *string = nil
	// BasevalueFlag means basevalue flag
	BasevalueFlag *string = nil
	// MspolicyFlag means mspolicy flag
	MspolicyFlag *int = nil
	// UuidFlag means uuid flag
	UuidFlag *string = nil
	// TestFlag means test flag
	TestFlag *bool = nil
	// Container Flag
	ConIdFlag   *string = nil
	ConTypeFlag *string = nil

	attesterConf *attesterConfig = nil
)

// InitFlags inits the server command flags.
func InitFlags() {
	log.Print("Init attester flags......")
	VersionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	ServerFlag = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	BasevalueFlag = pflag.StringP(lflagBasevalue, sflagBasevalue, "", helpBasevalue)
	MspolicyFlag = pflag.IntP(lflagMeasure, sflagMeasure, -1, helpMeasure)
	UuidFlag = pflag.StringP(lflagUuid, sflagUuid, "", helpUuid)
	TestFlag = pflag.BoolP(lflagTest, sflagTest, false, helpTest)
	ConIdFlag = pflag.String(sflagConId, "", helpConId)
	ConTypeFlag = pflag.String(sflagConType, "", helpConType)
	pflag.Parse()
}

// LoadConfigs searches and loads config from config.yaml file.
func LoadConfigs() {
	log.Print("Load attester Configs......")
	if attesterConf != nil {
		return
	}
	attesterConf = &attesterConfig{}
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
	attesterConf.server = viper.GetString(Server)
	attesterConf.basevalue = viper.GetString(Basevalue)
	attesterConf.mspolicy = viper.GetInt(Mspolicy)
	attesterConf.uuid = viper.GetString(Uuid)
	attesterConf.conId = viper.GetString(ConIdKey)
	attesterConf.conType = viper.GetString(ConTypeKey)
}

// HandleFlags handles the command flags.
func HandleFlags() {
	log.Print("Handle attester flags......")
	if VersionFlag != nil && *VersionFlag {
		log.Printf("TEE Remote Attester: %s\n", attesterVersion)
		os.Exit(0)
	}
	if ServerFlag != nil && *ServerFlag != "" {
		attesterConf.server = *ServerFlag
		log.Printf("TEE Server: %s", attesterConf.server) // just for test!
	}
	if BasevalueFlag != nil && *BasevalueFlag != "" {
		attesterConf.basevalue = *BasevalueFlag
		log.Printf("TEE Basevalue File Path: %s", attesterConf.basevalue) // just for test!
	}
	if MspolicyFlag != nil && *MspolicyFlag != -1 {
		attesterConf.mspolicy = *MspolicyFlag
		log.Printf("TEE Measurement: %d", attesterConf.mspolicy) // just for test!
	}
	if UuidFlag != nil && *UuidFlag != "" {
		attesterConf.uuid = *UuidFlag
		log.Printf("TEE Uuid: %s", attesterConf.uuid) // just for test!
	}
	if ConIdFlag != nil && *ConIdFlag != "" {
		attesterConf.conId = *ConIdFlag
		log.Printf("TEE container id: %s", attesterConf.conId) // just for test!
	}
	if ConTypeFlag != nil && *ConTypeFlag != "" {
		attesterConf.conType = *ConTypeFlag
		log.Printf("TEE container type: %s", attesterConf.conType) // just for test!
	}
	if TestFlag != nil && *TestFlag {
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
	case 0:
		log.Print("tee verify succeeded!")
	case -1:
		log.Print("tee verify nonce failed!")
	case -2:
		log.Print("tee verify signature failed!")
	case -3:
		log.Print("tee verify hash failed!")
	}

	log.Print("Stop Attester......")
}

func chenckContainerInfo(id, ctype string) error {
	// no container info input is valid
	if id == "" && ctype == "" {
		return nil
	}

	if id == "" || ctype == "" {
		return fmt.Errorf("id or type lacked")
	}
	switch strings.ToLower(ctype) {
	case "docker":
		if len(id) != 64 {
			return fmt.Errorf("invalid id length %d", len(id))
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

	err = chenckContainerInfo(attesterConf.conId, attesterConf.conType)
	if err != nil {
		return nil, err
	}
	ta.conId = attesterConf.conId
	ta.conType = attesterConf.conType
	return ta, nil
}

// remote invoke qca api to get the TA's info
func getReport(ta *trustApp) []byte {
	if ta == nil {
		log.Printf("invalid input ta")
		return nil
	}

	var info *qapi.GetReportRequest_ContainerInfo
	if ta.conId != "" || ta.conType != "" {
		info = &qapi.GetReportRequest_ContainerInfo{
			Id:   ta.conId,
			Type: ta.conType,
		}
	}

	reqID := qapi.GetReportRequest{
		Uuid:    ta.uuid,
		Nonce:   ta.usrdata,
		WithTcb: ta.withtcb,
		Info:    info,
	}

	rpyID, err := qapi.DoGetTeeReport(attesterConf.server, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, error: %v", err)
		return nil
	}
	log.Print("Get TA report succeeded!")
	ta.report = rpyID.GetTeeReport()
	return ta.report
}

// invoke verifier lib to verify
// int tee_verify_report(buffer_data *data_buf, buffer_data *nonce, container_info *info, int type, char *filename);
func tee_verify(ta *trustApp, mtype int, bv string) int {
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
	if ta.conId != "" && ta.conType != "" {
		var tmpInfo C.container_info
		cid := C.CString(ta.conId)
		defer C.free(unsafe.Pointer(cid))
		ctype := C.CString(ta.conType)
		defer C.free(unsafe.Pointer(ctype))
		tmpInfo.id.buf, tmpInfo.id.size = (*C.uchar)(cid), C.__uint32_t(len(ta.conId))
		tmpInfo._type.buf, tmpInfo._type.size = (*C.uchar)(ctype), C.__uint32_t(len(ta.conType))
		cinfo = &tmpInfo
	}

	// construct C filename
	cbv := C.CString(bv)
	defer C.free(unsafe.Pointer(cbv))

	result := C.tee_verify_report(&crep, &cnonce, cinfo, C.int(mtype), cbv)
	return int(result)
}
