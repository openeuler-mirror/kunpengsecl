// invoke qca lib to get info of given TA
package qcatools

/*
#cgo CFLAGS: -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lqca -Wl,-rpath=${SRCDIR}/../../../tverlib/simulator -lteec
#include "teeqca.h"
#include <string.h>

static uint8_t *createParamSet(uint32_t count, uint32_t data_size) {
	uint8_t *buf = malloc(sizeof(uint32_t) + count * sizeof(struct ra_params) + data_size);
	if (buf == NULL)
		return NULL;
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	pset->param_count = count;
    return buf;
}

static uint8_t *generateParamSetBufferProvisionNoAS() {
	uint8_t *buf = createParamSet(1, 0);
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	pset->params[0].tags = RA_TAG_HASH_TYPE;
	pset->params[0].data.integer = RA_ALG_SHA_256;
	return buf;
}

static uint8_t *generateParamSetBufferProvisionNoDAA() {
	return generateParamSetBufferProvisionNoAS();
}

static uint8_t *generateParamSetBufferProvisionDAA() {
	uint8_t name[] = "daa_grp_fp256bn";
	uint8_t *buf = createParamSet(2, sizeof(name));
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	pset->params[0].tags = RA_TAG_HASH_TYPE;
	pset->params[0].data.integer = RA_ALG_SHA_256;
	pset->params[1].tags = RA_TAG_CURVE_TYPE;
	pset->params[1].data.blob.data_len = sizeof(name);
	pset->params[1].data.blob.data_offset =
		sizeof(uint32_t) + pset->param_count * sizeof(struct ra_params);
	memcpy(buf+pset->params[1].data.blob.data_offset, name, sizeof(name));
	return buf;
}

static uint8_t *generateParamSetBufferGetReport(uint32_t scenario, bool with_tcb) {
	uint8_t *buf = NULL;
	if (scenario == RA_SCENARIO_AS_WITH_DAA)
		buf = createParamSet(3, 0);
	else
		buf = createParamSet(1, 0);

	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	pset->params[0].tags = RA_TAG_HASH_TYPE;
	pset->params[0].data.integer = RA_ALG_SHA_256;
	if (scenario == RA_SCENARIO_AS_WITH_DAA) {
		pset->params[1].tags = RA_TAG_WITH_TCB;
		pset->params[1].data.integer = with_tcb;
		pset->params[2].tags = RA_TAG_BASE_NAME;
		pset->params[2].data.blob.data_len = 0; // only support basename = NULL now
		pset->params[2].data.blob.data_offset =
			sizeof(uint32_t) + pset->param_count * sizeof(struct ra_params);
	}
	return buf;
}

static uint32_t getParamSetBufferSize(uint8_t *buf) {
	struct ra_params_set_t *pset = (struct ra_params_set_t *)buf;
	uint32_t size = sizeof(uint32_t) + pset->param_count * sizeof(struct ra_params);
	for (int i = 0; i < pset->param_count; i++) {
		if ((pset->params[i].tags & RA_BYTES) != 0) {
			size += pset->params[i].data.blob.data_len;
		}
	}
	return size;
}
*/
import "C"

import (
	"errors"
	"log"
	"unsafe"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// config info
	ConfName    = "config"
	ConfExt     = "yaml"
	strPath     = "."
	Server      = "qcaconfig.server"
	AKServer    = "qcaconfig.akserver"
	Scenario    = "qcaconfig.scenario"
	NoDaaACFile = "qcaconfig.nodaaacfile"
	DaaACFile   = "qcaconfig.daaacfile"
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

const (
	// app scenario
	RA_SCENARIO_NO_AS = int32(iota)
	RA_SCENARIO_AS_NO_DAA
	RA_SCENARIO_AS_WITH_DAA
)

type (
	Go_ra_buffer_data struct {
		Size uint32
		Buf  []uint8
	}
	qcaConfig struct {
		Server      string
		AKServer    string
		Scenario    int32
		NoDaaACFile string
		DaaACFile   string
	}
)

var (
	// server side config
	Qcacfg       *qcaConfig = nil
	defaultPaths            = []string{
		strPath,
	}
	ServerFlag   *string = nil
	ScenarioFlag *int32  = nil
)

func InitFlags() {
	log.Print("Init qca flags......")
	ServerFlag = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	ScenarioFlag = pflag.Int32P(lflagScenario, sflagScenario, 0, helpScenario)
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
	Qcacfg.AKServer = viper.GetString(AKServer)
	Qcacfg.Scenario = viper.GetInt32(Scenario)
	Qcacfg.NoDaaACFile = viper.GetString(NoDaaACFile)
	Qcacfg.DaaACFile = viper.GetString(DaaACFile)
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
	c_param_set.buf = C.generateParamSetBufferGetReport(C.__uint32_t(Qcacfg.Scenario), C.bool(with_tcb))
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	defer C.free(unsafe.Pointer(c_param_set.buf))
	// report conversion
	c_report.size = 0x4000
	up_report_buf := C.malloc(C.ulong(c_report.size))
	c_report.buf = (*C.uchar)(up_report_buf)
	defer C.free(up_report_buf)
	// tcb conversion
	c_with_tcb := C.bool(with_tcb)
	// result of function call
	teec_result := C.RemoteAttestReport(*(*C.TEEC_UUID)(c_ta_uuid), &c_usr_data, &c_param_set, &c_report, c_with_tcb) // can not put Go pointer as parameter in C function!!!
	if int(teec_result) != 0 {
		log.Print("Get TA report failed!")
		return nil
	}

	log.Print("Generate TA report succeeded!")

	// format conversion: C -> Go
	Report := []uint8(C.GoBytes(unsafe.Pointer(c_report.buf), C.int(c_report.size)))

	//ioutil.WriteFile("report.orig", Report, 0644)

	return Report
}

func provisionNoAS() int {
	c_param_set := C.struct_ra_buffer_data{}
	c_out := C.struct_ra_buffer_data{}
	c_param_set.buf = C.generateParamSetBufferProvisionNoAS()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	c_out.size = 0x2000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))
	// set app scenario
	c_scenario := C.uint(RA_SCENARIO_NO_AS)

	result := C.RemoteAttestProvision(c_scenario, &c_param_set, &c_out)
	C.free(unsafe.Pointer(c_out.buf))
	C.free(unsafe.Pointer(c_param_set.buf))
	return int(result)
}

func provisionNoDAA() ([]byte, error) {
	c_param_set := C.struct_ra_buffer_data{}
	c_out := C.struct_ra_buffer_data{}
	c_param_set.buf = C.generateParamSetBufferProvisionNoDAA()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	c_out.size = 0x2000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))
	// set app scenario
	c_scenario := C.uint(RA_SCENARIO_AS_NO_DAA)

	result := C.RemoteAttestProvision(c_scenario, &c_param_set, &c_out)
	if result != 0 {
		return nil, errors.New("invoke remoteAttestProvision failed")
	}
	akcertByte := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))

	return akcertByte, nil
}

func provisionDAA() ([]byte, error) {
	c_param_set := C.struct_ra_buffer_data{}
	c_out := C.struct_ra_buffer_data{}
	c_param_set.buf = C.generateParamSetBufferProvisionDAA()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	c_out.size = 0x2000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))
	// set app scenario
	c_scenario := C.uint(RA_SCENARIO_AS_WITH_DAA)

	result := C.RemoteAttestProvision(c_scenario, &c_param_set, &c_out)
	if result != 0 {
		return nil, errors.New("invoke remoteAttestProvision failed")
	}
	akcertByte := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))

	return akcertByte, nil
}

func GenerateAKCert() ([]byte, error) {
	switch Qcacfg.Scenario {
	case RA_SCENARIO_NO_AS:
		result := provisionNoAS()
		if result != 0 {
			log.Print("NoAS scenario: Generate RSA AK and AK Cert failed!")
		} else {
			log.Print("NoAS scenario: Generate RSA AK and AK Cert succeeded!")
		}
	case RA_SCENARIO_AS_NO_DAA:
		akcert, err := provisionNoDAA()
		if err != nil {
			log.Print("NoDAA scenario: Generate RSA AK and AK Cert failed!")
			return nil, err
		}
		log.Print("NoDAA scenario: Generate RSA AK and AK Cert succeeded!")
		//ioutil.WriteFile("akcert-nodaa.orig", akcert, 0644)
		return akcert, nil
	case RA_SCENARIO_AS_WITH_DAA:
		akcert, err := provisionDAA()
		if err != nil {
			log.Print("DAA scenario: Generate AK and AK Cert failed!")
			return nil, err
		}
		log.Print("DAA scenario: Generate AK and AK Cert succeeded!")
		//ioutil.WriteFile("akcert-daa.orig", akcert, 0644)
		return akcert, nil
	default:
		return nil, errors.New("scenario is not supported yet")
	}
	return nil, errors.New("do not need to access as")
}

func SaveAKCert(cert []byte) error {
	cert_buf := C.CBytes(cert)
	cert_data := C.struct_ra_buffer_data{0, (*C.uchar)(cert_buf)}
	cert_data.size = C.__uint32_t(len(cert))
	defer C.free(cert_buf)

	result := C.RemoteAttestSaveAKCert(&cert_data)
	if result != 0 {
		log.Print("Save AK Cert failed!")
		return errors.New("invoke RemoteAttestSaveAkCert failed")
	}
	return nil
}
