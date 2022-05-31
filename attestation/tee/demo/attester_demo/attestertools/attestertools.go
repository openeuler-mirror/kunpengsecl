// invoke attester lib and get info from qapi
package attestertools

/*
#cgo CFLAGS: -I../../../tverlib/verifier
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/verifier -lteeverifier -Wl,-rpath=${SRCDIR}/../../../tverlib/verifier
#include "teeverifier.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
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
	// config file name
	ConfName = "config"
	ConfExt  = "yaml"
	// attester config path
	strPath = "."
	// attester config key
	Server    = "attesterconfig.server"
	Basevalue = "attesterconfig.basevalue"
	Mspolicy  = "attesterconfig.mspolicy"
	Uuid      = "attesterconfig.uuid"
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
		strPath,
	}
	VersionFlag   *bool           = nil
	ServerFlag    *string         = nil
	BasevalueFlag *string         = nil
	MspolicyFlag  *int            = nil
	UuidFlag      *string         = nil
	TestFlag      *bool           = nil
	attesterConf  *attesterConfig = nil
	up_rep_buf    unsafe.Pointer
	up_non_buf    unsafe.Pointer
)

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
		var s_nonce string = "challenge"
		nonce := []byte(s_nonce)
		test_ta.usrdata = nonce
	}
}

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
		log.Print("tee verify all successed!")
	case -1:
		log.Print("tee verify nonce failed!")
	case -2:
		log.Print("tee verify signature failed!")
	case -3:
		log.Print("tee verify hash failed!")
	}

	log.Print("Stop Attester......")
}

// Initialize the parameters of TA
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

	// Verify that if the Nonce value is tampered with
	// for i := 0; i < len(ta.usrdata); i++ {
	//	if ta.usrdata.Buf[i] != rpyID.Nonce[i] {
	//		log.Print("Nonce value returned does not match!")
	//		return ta.report
	//	}
	//}
	//log.Print("The returned nonce value is not modified unexpectedly!")

	ta.report = rpyID.GetTeeReport()

	/* Test whether the expected data is received */
	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(ta.report.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, ta.report.Buf[i])
	// }
	// fmt.Print("\n")

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
