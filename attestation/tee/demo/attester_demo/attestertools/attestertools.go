// invoke attester lib and get info from qapi
package attestertools

/*
#cgo CFLAGS: -I/usr/local/include
#cgo LDFLAGS: -L/usr/local/lib -lcrypto
#include "../../../tverlib/verifier/verifier.h"
#include "../../../tverlib/verifier/verifier.c"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"log"
	"net"
	"os"
	"unsafe"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
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
	// app usage scenario
	lflagScenario = "scenario"
	sflagScenario = "C"
	helpScenario  = "set the app usage scenario"
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
	Scenario  = "attesterconfig.scenario"
)

type (
	trustApp struct {
		ctx      context.Context
		uuid     int64
		usrdata  *qapi.Buffer
		paramset *qapi.Buffer
		report   *qapi.Buffer
		withtcb  bool
	}
	attesterConfig struct {
		server    string
		basevalue string
		mspolicy  int
		uuid      int64
		scenario  int
	}
)

var (
	test_ta *trustApp = &trustApp{
		ctx:      context.Background(),
		uuid:     -1,
		usrdata:  &qapi.Buffer{},
		paramset: &qapi.Buffer{},
		report:   &qapi.Buffer{},
		withtcb:  false,
	}
	verify_result bool = false
	defaultPaths       = []string{
		strPath,
	}
	VersionFlag   *bool           = nil
	ServerFlag    *string         = nil
	BasevalueFlag *string         = nil
	MspolicyFlag  *int            = nil
	UuidFlag      *int64          = nil
	ScenarioFlag  *int            = nil
	attesterConf  *attesterConfig = nil
	up_rep_buf    unsafe.Pointer
	up_mf_buf     unsafe.Pointer
)

func InitFlags() {
	log.Print("Init flags......")
	VersionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	ServerFlag = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	BasevalueFlag = pflag.StringP(lflagBasevalue, sflagBasevalue, "", helpBasevalue)
	MspolicyFlag = pflag.IntP(lflagMeasure, sflagMeasure, -1, helpMeasure)
	UuidFlag = pflag.Int64P(lflagUuid, sflagUuid, -1, helpUuid)
	ScenarioFlag = pflag.IntP(lflagScenario, sflagScenario, 0, helpScenario)
	pflag.Parse()
}

func LoadConfigs() {
	log.Print("Load Configs......")
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
	attesterConf.uuid = viper.GetInt64(Uuid)
	attesterConf.scenario = viper.GetInt(Scenario)
}

func HandleFlags() {
	log.Print("Handle flags......")
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
	if UuidFlag != nil && *UuidFlag != -1 {
		attesterConf.uuid = *UuidFlag
		log.Printf("TEE Uuid: %d", attesterConf.uuid) // just for test!
	}
	if ScenarioFlag != nil && *ScenarioFlag != 0 {
		attesterConf.scenario = *ScenarioFlag
		log.Printf("TEE Scenario: %d", attesterConf.scenario)
	}
}

func StartAttester() {
	log.Print("Start Attester......")
	conn, err := net.Dial("tcp", attesterConf.server)
	if err != nil {
		log.Printf("Dial %s failed, err: %v", attesterConf.server, err)
		return
	}
	defer conn.Close()
	if conn != nil {
		log.Printf("Connection %s success!", attesterConf.server)
		test_ta, err = iniTAParameter(test_ta)
		if err != nil {
			log.Printf("Init TA parameter failed! %v", err)
		}
		test_ta.report = getReport(test_ta)
		verify_result = verifySig(test_ta.report)
		if !verify_result {
			log.Print("Verify signature failed!")
		} else {
			log.Print("Verify signature success!")
		}
		verify_result = validate(test_ta.report, attesterConf.mspolicy, attesterConf.basevalue)
		if !verify_result {
			log.Print("validate failed!")
		} else {
			log.Print("validate success!")
		}
	} else {
		log.Printf("Connection %s failed!", attesterConf.server)
	}

	log.Print("Stop Attester......")
}

// Initialize the parameters of TA
func iniTAParameter(ta *trustApp) (*trustApp, error) {
	ta.uuid = attesterConf.uuid
	// create nonce value to defend against replay attacks
	nonce := make([]byte, 8)
	size, err := rand.Read(nonce)
	if err != nil {
		return test_ta, err
	}
	ta.usrdata.Size = uint32(size)
	ta.usrdata.Buf = append(ta.usrdata.Buf, nonce...)
	ta.paramset.Size = 1
	ta.paramset.Buf = append(ta.paramset.Buf, byte(attesterConf.scenario))

	return ta, nil
}

// remote invoke qca api to get the TA's info
func getReport(ta *trustApp) *qapi.Buffer {
	reqID := qapi.GetReportRequest{
		Uuid:     ta.uuid,
		UsrData:  ta.usrdata,
		ParamSet: ta.paramset,
		Report:   ta.report,
		WithTcb:  ta.withtcb,
	}

	rpyID, err := qapi.DoGetReport(ta.ctx, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, error: %v", err)
		return ta.report
	}

	// Verify that if the Nonce value is tampered with
	for i := 0; i < int(ta.usrdata.Size); i++ {
		if ta.usrdata.Buf[i] != rpyID.Nonce[i] {
			log.Print("Nonce value returned does not match!")
			return ta.report
		}
	}
	log.Print("The returned nonce value is not modified unexpectedly!")

	ta.report.Size = rpyID.TeeReport.Size
	ta.report.Buf = rpyID.TeeReport.Buf

	/* Test whether the expected data is received */
	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(ta.report.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, ta.report.Buf[i])
	// }
	// fmt.Print("\n")

	return ta.report
}

// invoke verifier lib to verify
func verifySig(rep *qapi.Buffer) bool {
	var crep C.buffer_data
	rep = &qapi.Buffer{}
	crep.size = C.__uint32_t(rep.Size)
	up_rep_buf = C.CBytes(rep.Buf)
	defer C.free(up_rep_buf)
	crep.buf = (*C.uchar)(up_rep_buf)
	// result := C.tee_verify_signature(&crep)
	result := false
	return result
}

// invoke verifier lib to validate
func validate(mf *qapi.Buffer, mtype int, bv string) bool {
	_ = mtype // ignore the unused warning
	var crep C.buffer_data
	mf = &qapi.Buffer{}
	cbv := C.CString(bv)
	defer C.free(unsafe.Pointer(cbv))
	crep.size = C.__uint32_t(mf.Size)
	up_mf_buf = C.CBytes(mf.Buf)
	defer C.free(up_mf_buf)
	crep.buf = (*C.uchar)(up_mf_buf)
	// result := C.tee_verify(&crep, C.int(mtype), cbv)
	result := false
	return result
}
