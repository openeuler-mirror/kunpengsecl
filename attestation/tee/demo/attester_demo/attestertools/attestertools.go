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
	"log"
	"os"
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
	Uuid = "attesterconfig.uuid"
)

type (
	trustApp struct {
		ctx     context.Context
		uuid    []byte
		usrdata []byte
		report  []byte
		withtcb bool
	}
	attesterConfig struct {
		server    string
		basevalue string
		mspolicy  int
		uuid      string
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
	TestFlag     *bool           = nil
	attesterConf *attesterConfig = nil
	up_rep_buf   unsafe.Pointer
	up_non_buf   unsafe.Pointer
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
	if TestFlag != nil && *TestFlag {
		testmode = true
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
	}
	test_ta.report = getReport(test_ta)
	verify_result = tee_verify(test_ta.report, test_ta.usrdata, attesterConf.mspolicy, attesterConf.basevalue)
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

// iniTAParameter initializes the parameters of TA
func iniTAParameter(ta *trustApp, m bool) (*trustApp, error) {
	id, err := uuid.Parse(attesterConf.uuid)
	if err != nil {
		return test_ta, err
	}
	ta.uuid, err = id.MarshalBinary()
	if err != nil {
		return test_ta, err
	}
	// create nonce value to defend against replay attacks
	if !m {
		nonce := make([]byte, 64)
		_, err = rand.Read(nonce)
		if err != nil {
			return test_ta, err
		}
		ta.usrdata = nonce
	}
	return ta, nil
}

// remote invoke qca api to get the TA's info
func getReport(ta *trustApp) []byte {
	reqID := qapi.GetReportRequest{
		Uuid:    ta.uuid,
		Nonce:   ta.usrdata,
		WithTcb: ta.withtcb,
	}

	rpyID, err := qapi.DoGetTeeReport(attesterConf.server, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, error: %v", err)
		return ta.report
	}
	log.Print("Get TA report succeeded!")
	ta.report = rpyID.GetTeeReport()
	return ta.report
}

// invoke verifier lib to verify
func tee_verify(rep []byte, nonce []byte, mtype int, bv string) int {
	var crep C.buffer_data
	var cnonce C.buffer_data
	cbv := C.CString(bv)
	defer C.free(unsafe.Pointer(cbv))
	crep.size = C.__uint32_t(len(rep))
	up_rep_buf = C.CBytes(rep)
	defer C.free(up_rep_buf)
	crep.buf = (*C.uchar)(up_rep_buf)
	cnonce.size = C.__uint32_t(len(nonce))
	up_non_buf = C.CBytes(nonce)
	defer C.free(up_non_buf)
	cnonce.buf = (*C.uchar)(up_non_buf)
	result := C.tee_verify_report(&crep, &cnonce, C.int(mtype), cbv)
	return int(result)
}
