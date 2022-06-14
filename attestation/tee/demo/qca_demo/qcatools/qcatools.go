// invoke qca lib to get info of given TA
package qcatools

/*
#cgo CFLAGS: -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lqca -Wl,-rpath=${SRCDIR}/../../../tverlib/simulator -lteec
#include "teeqca.h"

static uint8_t *createParamSet(uint32_t count) {
	uint8_t *buf = malloc(sizeof(uint32_t) + count * sizeof(struct ra_params));
	if (buf == NULL)
		return NULL;
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	pset->param_count = count;
    return buf;
}

static uint8_t *fillParamSetInteger(uint8_t *ps, uint32_t idx, uint32_t value) {
	struct ra_params_set_t *pset = (struct ra_params_set_t *)ps;
	pset->params[idx].tags = RA_TAG_HASH_TYPE;
	pset->params[idx].data.integer = value;
	return ps;
}

static uint8_t *generateParamSetBuffer() {
	uint8_t *buf = createParamSet(1);
	fillParamSetInteger(buf, 0, RA_ALG_SHA_256);
	return buf;
}

static uint32_t getParamSetBufferSize(uint8_t *buf) {
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	return sizeof(uint32_t) + pset->param_count * sizeof(struct ra_params);
}
*/
import "C"

import (
	"log"
	"unsafe"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// config info
	ConfName = "config"
	ConfExt  = "yaml"
	strPath  = "."
	Server   = "qcaconfig.server"
	Scenario = "qcaconfig.scenario"
	/*** cmd flags ***/
	// server open ip:port
	lflagServer = "server"
	sflagServer = "S"
	helpServer  = "specify the IP address of the port can be connected"
	// app usage scenario
	lflagScenario = "scenario"
	sflagScenario = "C"
	helpScenario  = "set the app usage scenario"
)

type (
	Go_ra_buffer_data struct {
		Size uint32
		Buf  []uint8
	}
	qcaConfig struct {
		Server   string
		Scenario int
	}
)

var (
	// server side config
	Qcacfg       *qcaConfig = nil
	defaultPaths            = []string{
		strPath,
	}
	ServerFlag   *string = nil
	ScenarioFlag *int    = nil
)

func InitFlags() {
	log.Print("Init qca flags......")
	ServerFlag = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	ScenarioFlag = pflag.IntP(lflagScenario, sflagScenario, 0, helpScenario)
	pflag.Parse()
}

func LoadConfigs() {
	log.Print("Load qca Configs......")
	if Qcacfg != nil {
		return
	}
	Qcacfg = &qcaConfig{}
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
	Qcacfg.Server = viper.GetString(Server)
	Qcacfg.Scenario = viper.GetInt(Scenario)
}

func HandleFlags() {
	log.Print("Handle qca flags......")

	if ServerFlag != nil && *ServerFlag != "" {
		Qcacfg.Server = *ServerFlag
	}
	if ScenarioFlag != nil && *ScenarioFlag != 0 {
		Qcacfg.Scenario = *ScenarioFlag
	}
}

func reverseEndian(num []byte) {
	for i := 0; i < len(num)/2; i++ {
		num[i], num[len(num)-1-i] = num[len(num)-1-i], num[i]
	}
}

func adapt2TAUUID(uuid []byte) {
	reverseEndian(uuid[:4])
	reverseEndian(uuid[4:6])
	reverseEndian(uuid[6:8])
}

func GetTAReport(ta_uuid []byte, usr_data []byte, with_tcb bool) []byte {
	// store C data which convert from Go
	c_usr_data := C.struct_ra_buffer_data{}
	c_param_set := C.struct_ra_buffer_data{}
	c_report := C.struct_ra_buffer_data{}
	c_with_tcb := C.bool(false)

	/*** format conversion: Go -> C ***/
	// uuid conversion
	adapt2TAUUID(ta_uuid)
	c_ta_uuid := C.CBytes(ta_uuid)
	defer C.free(c_ta_uuid)
	// usrdata conversion
	c_usr_data.size = C.__uint32_t(len(usr_data))
	up_usr_data_buf := C.CBytes(usr_data)
	c_usr_data.buf = (*C.uchar)(up_usr_data_buf)
	defer C.free(up_usr_data_buf)
	// paramset conversion
	c_param_set.buf = C.generateParamSetBuffer()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	defer C.free(unsafe.Pointer(c_param_set.buf))
	// report conversion
	c_report.size = 0x4000
	up_report_buf := C.malloc(C.ulong(c_report.size))
	c_report.buf = (*C.uchar)(up_report_buf)
	defer C.free(up_report_buf)
	// tcb conversion
	c_with_tcb = C.bool(with_tcb)
	// result of function call
	teec_result := C.RemoteAttestReport(*(*C.TEEC_UUID)(c_ta_uuid), &c_usr_data, &c_param_set, &c_report, c_with_tcb) // can not put Go pointer as parameter in C function!!!
	if int(teec_result) != 0 {
		log.Print("Get TA report failed!")
		return nil
	}

	log.Print("Generate TA report succeeded!")

	// format conversion: C -> Go
	Report := []uint8(C.GoBytes(unsafe.Pointer(c_report.buf), C.int(c_report.size)))

	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(report.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, report.Buf[i])
	// }

	return Report
}

func provisionNoAS() int {
	c_param_set := C.struct_ra_buffer_data{}
	c_out := C.struct_ra_buffer_data{}
	c_param_set.buf = C.generateParamSetBuffer()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	c_out.size = 0x2000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))
	// set app scenario
	c_scenario := C.uint(Qcacfg.Scenario)

	result := C.RemoteAttestProvision(c_scenario, &c_param_set, &c_out)
	C.free(unsafe.Pointer(c_out.buf))
	C.free(unsafe.Pointer(c_param_set.buf))
	return int(result)
}

func HandleConnection() {
	result := provisionNoAS()
	if result != 0 {
		log.Print("Generate RSA AK and AK Cert failed!")
		return
	}
	log.Print("Generate RSA AK and AK Cert succeeded!")
}
