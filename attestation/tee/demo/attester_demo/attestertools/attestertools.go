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
	// basevalue set
	lflagBasevalue = "basevalue"
	sflagBasevalue = "B"
	helpBasevalue  = "set the reference value to be compared"
	// measure policy set
	lflagMeasure = "mspolicy"
	sflagMeasure = "M"
	helpMeasure  = "set a measurement policy to be used"
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
	testReport struct {
		teerep *qapi.Buffer
	}
	attesterConfig struct {
		server    string
		basevalue string
		mspolicy  int
	}
)

var (
	ini_buf [100]byte
	test_ta *trustApp = &trustApp{
		ctx:  context.Background(),
		uuid: 1,
		usrdata: &qapi.Buffer{
			Size: 100,
			Buf:  ini_buf[:],
		},
		paramset: &qapi.Buffer{
			Size: 100,
			Buf:  ini_buf[:],
		},
		report: &qapi.Buffer{
			Size: 100,
			Buf:  ini_buf[:],
		},
		withtcb: false,
	}
	verify_result bool = false
	defaultPaths       = []string{
		strPath,
	}
	VersionFlag   *bool           = nil
	ServerFlag    *string         = nil
	BasevalueFlag *string         = nil
	MspolicyFlag  *int            = nil
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
}

func HandleFlags() {
	log.Print("Handle flags......")
	if VersionFlag != nil && *VersionFlag {
		log.Printf("TEE Remote Attester: %s\n", attesterVersion)
		os.Exit(0)
	}
	if ServerFlag != nil && *ServerFlag != "" {
		attesterConf.server = *ServerFlag
	}
	if BasevalueFlag != nil && *BasevalueFlag != "" {
		attesterConf.basevalue = *BasevalueFlag
	}
	if MspolicyFlag != nil && *MspolicyFlag != -1 {
		attesterConf.mspolicy = *MspolicyFlag
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
		rep := getReport(test_ta)
		verify_result = verifySig(rep)
		if !verify_result {
			log.Print("Verify signature failed!")
		} else {
			log.Print("Verify signature success!")
		}
		verify_result = validate(rep, attesterConf.mspolicy, attesterConf.basevalue)
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

// remote invoke qca api to get the TA's info
func getReport(ta *trustApp) testReport {
	result := testReport{}
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
		return result
	}

	result = testReport{
		teerep: rpyID.GetTeeReport(),
	}
	/* Test whether the expected data is received */
	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(result.teerep.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, result.teerep.Buf[i])
	// }
	// fmt.Print("\n")

	return result
}

// invoke verifier lib to verify
func verifySig(rep testReport) bool {
	var crep C.buffer_data
	crep.size = C.__uint32_t(rep.teerep.Size)
	up_rep_buf = C.CBytes(rep.teerep.Buf)
	defer C.free(up_rep_buf)
	crep.buf = (*C.uchar)(up_rep_buf)
	// result := C.VerifySignature(&crep)
	result := false
	return result
}

// invoke verifier lib to validate
func validate(mf testReport, mtype int, bv string) bool {
	var crep C.buffer_data
	cbv := C.CString(bv)
	defer C.free(unsafe.Pointer(cbv))
	crep.size = C.__uint32_t(mf.teerep.Size)
	up_mf_buf = C.CBytes(mf.teerep.Buf)
	defer C.free(up_mf_buf)
	crep.buf = (*C.uchar)(up_mf_buf)
	result := C.VerifyManifest(&crep, C.int(mtype), cbv)
	return bool(result)
}
