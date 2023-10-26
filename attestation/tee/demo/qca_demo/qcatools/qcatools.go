/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli/wanghaijing
Create: 2022-05-01
Description: invoke qca lib to get info of given TA
*/

package qcatools

/*
#cgo CFLAGS: -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lqca -lteec
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
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"unsafe"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// config info
	// ConfName means config file name
	ConfName = "config"
	// ConfExt means config file name suffix
	ConfExt      = "yaml"
	strLocalConf = "."
	strHomeConf  = "$HOME/.config/attestation/qcaserver"
	strSysConf   = "/etc/attestation/qcaserver"
	// Server means qcaconfig server
	Server = "qcaconfig.server"
	// AKServer means qcaconfig akserver
	AKServer = "qcaconfig.akserver"
	// Scenario means qcaconfig scenario
	Scenario = "qcaconfig.scenario"
	// NoDaaACFile means qcaconfig nodaaacfile
	NoDaaACFile = "qcaconfig.nodaaacfile"
	// DaaACFile means qcaconfig daaacfile
	DaaACFile = "qcaconfig.daaacfile"
	// virtual server to support virtual remote attest
	VirtServer    = "qcaconfig.virtual.server"
	VirtHealthChk = "qcaconfig.virtual.healthcheck"
	/*** cmd flags ***/
	// server open ip:port
	lflagServer = "server"
	sflagServer = "S"
	helpServer  = "specify the IP address of the port can be connected"
	// app usage scenario
	lflagScenario = "scenario"
	sflagScenario = "C"
	helpScenario  = "set the app usage scenario"
	// specify virtual server to support virtual remote attest
	lflagVirtSupport   = "virtual"
	sflagVirtSupport   = "V"
	helpVirtSupport    = "is support remote attest"
	lflagVirtServer    = "virtualserver"
	sflagVirtServer    = "A"
	helpVirtServer     = "virtual server addr"
	lflagVirtHealthChk = "healthcheck"
	sflagVirtHealthChk = "H"
	helpVirtHealthChk  = "virtual connect health check"
	// RemoteAttest Handler
	RAProvisionInHandler  = "provisioning-input"
	RAProvisionOutHandler = "provisioning-output"
	RAReportInHandler     = "report-input"
	RAReportOutHandler    = "report-output"
	RASaveAKCertHandler   = "saveakcert-input"
)

const (
	ZERO_VALUE                  = 0
	UINT32_BYTES_LENGTH         = 4
	UINT64_BYTES_LENGTH         = 8
	NoAS_ERROR_RETURN_CODE      = 1
	TYPE_CONV_ERROR_RETURN_CODE = -1
	// alg type
	RA_ALG_RSA_3072        = 0x20000
	RA_ALG_RSA_4096        = 0x20001 // PSS padding
	RA_ALG_SHA_256         = 0x20002
	RA_ALG_SHA_384         = 0x20003
	RA_ALG_SHA_512         = 0x20004
	RA_ALG_ECDSA           = 0x20005
	RA_ALG_ED25519         = 0x20006
	RA_ALG_SM2_DSA_SM3     = 0x20007
	RA_ALG_SM3             = 0x20008
	RA_ALG_DAA_GRP_FP256BN = 0x20009
	// app scenario
	RA_SCENARIO_NO_AS_INT       = 0
	RA_SCENARIO_AS_NO_DAA_INT   = 1
	RA_SCENARIO_AS_WITH_DAA_INT = 2
)

const (
	// version type: "TEE.RA.[Major].[Minor]"
	RA_VERSION = "TEE.RA.1.0"
	// app scenario
	RA_SCENARIO_NO_AS       = "sce_no_as"
	RA_SCENARIO_AS_NO_DAA   = "sce_as_no_daa"
	RA_SCENARIO_AS_WITH_DAA = "sce_as_with_daa"
	// hash algorithm
	RA_HASH_ALG_SHA256 = "HS256"
	// daa curve type
	RA_DAA_CURVE_FP256BN = "Fp256BN"
	RA_DAA_CURVE_FP512BN = "Fp512BN"
)

func typeConv(in string) int32 {
	switch in {
	case RA_SCENARIO_NO_AS:
		return RA_SCENARIO_NO_AS_INT
	case RA_SCENARIO_AS_NO_DAA:
		return RA_SCENARIO_AS_NO_DAA_INT
	case RA_SCENARIO_AS_WITH_DAA:
		return RA_SCENARIO_AS_WITH_DAA_INT

	}
	return TYPE_CONV_ERROR_RETURN_CODE
}

type (
	// Go_ra_buffer_data is used to store ra buffer data
	Go_ra_buffer_data struct {
		Size uint32
		Buf  []uint8
	}
	qcaConfig struct {
		Server        string
		AKServer      string
		Scenario      int32
		NoDaaACFile   string
		DaaACFile     string
		VirtSupport   bool
		VirtServer    string
		VirtHealthChk int32
	}
)

var (
	// server side config
	// Qcacfg means qca config
	Qcacfg       *qcaConfig = nil
	defaultPaths            = []string{
		strLocalConf,
		strHomeConf,
		strSysConf,
	}
	// ServerFlag means server flag
	ServerFlag *string = nil
	// ScenarioFlag means scenario flag
	ScenarioFlag      *int32  = nil
	VirtSupportFlag   *bool   = nil
	VirtServerFlag    *string = nil
	VirtHealthChkFlag *int32  = nil
)

// InitFlags inits the qca server command flags.
func InitFlags() {
	log.Print("Init qca flags......")
	ServerFlag = pflag.StringP(lflagServer, sflagServer, "", helpServer)
	ScenarioFlag = pflag.Int32P(lflagScenario, sflagScenario, 0, helpScenario)
	VirtSupportFlag = pflag.BoolP(lflagVirtSupport, sflagVirtSupport, false, helpVirtSupport)
	VirtServerFlag = pflag.StringP(lflagVirtServer, sflagVirtServer, "", helpVirtServer)
	VirtHealthChkFlag = pflag.Int32P(lflagVirtHealthChk, sflagVirtHealthChk, 0, helpVirtHealthChk)
	pflag.Parse()
}

// LoadConfigs searches and loads config from config.yaml file.
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
	Qcacfg.VirtServer = viper.GetString(VirtServer)
	Qcacfg.VirtHealthChk = viper.GetInt32(VirtHealthChk)
}

// HandleFlags handles the command flags.
func HandleFlags() {
	log.Print("Handle qca flags......")

	if ServerFlag != nil && *ServerFlag != "" {
		Qcacfg.Server = *ServerFlag
	}
	if ScenarioFlag != nil && *ScenarioFlag != 0 {
		Qcacfg.Scenario = *ScenarioFlag
	}

	if VirtSupportFlag != nil {
		Qcacfg.VirtSupport = *VirtSupportFlag
	}
	if VirtServerFlag != nil && *VirtServerFlag != "" {
		Qcacfg.VirtServer = *VirtServerFlag
	}
	if VirtHealthChkFlag != nil && *VirtHealthChkFlag > 0 {
		Qcacfg.VirtHealthChk = *VirtHealthChkFlag
	}
}

// GetQcaServer returns the qca service server configuration.
func GetQcaServer() string {
	if Qcacfg == nil {
		return ""
	}
	return Qcacfg.Server
}

// SetScenario sets the qca service scenario configuration.
func SetScenario(s int32) {
	Qcacfg.Scenario = s
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

type (
	VirtualGuestInfo struct {
		Id   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}
	reportInPl struct {
		Version  string            `json:"version,omitempty"`        // VERSION_TYPE
		Nonce    string            `json:"nonce,omitempty"`          // BASE64_TYPE
		Uuid     string            `json:"uuid,omitempty"`           // 待证明的TA UUID的hex字符串描述，字母小写，如"e08f7eca-e875-440e-9ab0-5f381136c600"
		Hash_alg string            `json:"hash_alg,omitempty"`       // HASH_ALG_TYPE
		With_tcb bool              `json:"with_tcb,omitempty"`       // BOOLEAN_TYPE, 当前只能是 “FALSE”
		Daa_bsn  *string           `json:"daa_bsn,omitempty"`        // BASE64_TYPE, BASE64 of DAA用户挑选出来的basename
		Info     *VirtualGuestInfo `json:"container_info,omitempty"` // 名字兼容tee里名字
	}
	reportInParam struct {
		Handler string     `json:"handler,omitempty"`
		Payload reportInPl `json:"payload,omitempty"`
	}
)

func forwardReportReq(inparam []byte, out_len uint32, info *VirtualGuestInfo) ([]byte, error) {
	var report []byte
	var err error
	switch {
	// host request
	case info == nil || (info.Id == "" && info.Type == ""):
		log.Println("Deal host TA report request")
		report, err = CallCRemoteAttest(inparam, out_len)
		if err != nil {
			log.Printf("Get host ta report failed, %v", err)
			return nil, err
		}
	// virtual guest request
	default:
		log.Println("Deal virtaul guest TA report request")
		report, err = dealVirtualTAReq(info, inparam)
		if err != nil {
			log.Printf("Get docker ta report failed, %v", err)
			return nil, err
		}
	}

	log.Print("Generate TA report succeeded!")
	return report, nil
}

// GetTAReport gets TA trusted report information.
func GetTAReport(ta_uuid []byte, usr_data []byte, with_tcb bool, info *VirtualGuestInfo) ([]byte, error) {
	n := base64.RawURLEncoding.EncodeToString(usr_data)
	id, err := uuid.FromBytes(ta_uuid)
	if err != nil {
		log.Printf("wrong uuid in parameters, %v", err)
		return nil, err
	}

	// in parameters
	pl := reportInPl{
		Version:  RA_VERSION,
		Nonce:    n,
		Uuid:     id.String(),
		Hash_alg: RA_HASH_ALG_SHA256,
		With_tcb: with_tcb, // false
		Daa_bsn:  nil,      // line73 only support basename = NULL now
		Info:     info,
	}
	inparam := reportInParam{
		Handler: RAReportInHandler,
		Payload: pl,
	}
	inparamjson, err := json.Marshal(inparam)
	if err != nil {
		log.Printf("Encode GetTAReport json message error, %v", err)
		return nil, err
	}

	return forwardReportReq(inparamjson, 0x3000, info)
}

/*
func GetTAReport(ta_uuid []byte, usr_data []byte, with_tcb bool) []byte {
	// store C data which convert from Go
	c_usr_data := C.struct_ra_buffer_data{}
	c_param_set := C.struct_ra_buffer_data{}
	c_report := C.struct_ra_buffer_data{}

	// format conversion: Go -> C
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
	// can not put Go pointer as parameter in C function!!!
	teec_result := C.RemoteAttestReport(*(*C.TEEC_UUID)(c_ta_uuid), &c_usr_data, &c_param_set, &c_report, c_with_tcb)
	if int(teec_result) != 0 {
		log.Print("Get TA report failed!")
		return nil
	}

	log.Print("Generate TA report succeeded!")

	// format conversion: C -> Go
	Report := []uint8(C.GoBytes(unsafe.Pointer(c_report.buf), C.int(c_report.size)))

	return Report
}
*/

type provisionInPl struct {
	Version     string  `json:"version,omitempty"`
	Scenario    string  `json:"scenario,omitempty"`
	Hash_alg    string  `json:"hash_alg,omitempty"`
	Daa_g1_name *string `json:"daa_g1_name,omitempty"`
}
type provisionInParam struct {
	Handler string        `json:"handler,omitempty"`
	Payload provisionInPl `json:"payload,omitempty"`
}

func provisionNoAS() (int, error) {
	inpayload := provisionInPl{RA_VERSION, RA_SCENARIO_NO_AS, RA_HASH_ALG_SHA256, nil}
	inparam := provisionInParam{RAProvisionInHandler, inpayload}
	inparamjson, err := json.Marshal(inparam)
	log.Printf("test: no as provision. in data2 = {%s}", string(inparamjson))
	if err != nil {
		log.Printf("Encode NoAS json message error, %v", err)
		return NoAS_ERROR_RETURN_CODE, err
	}

	/*** format conversion: Go -> C ***/
	// in parameter conversion
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(inparamjson))
	up_c_in := C.CBytes(inparamjson)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	c_out := C.struct_ra_buffer_data{}
	c_out.size = 0x3000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))

	result := C.RemoteAttest(&c_in, &c_out)
	C.free(unsafe.Pointer(c_out.buf))

	return int(result), nil
}

func provisionNoDAA() ([]byte, error) {
	inpayload := provisionInPl{RA_VERSION, RA_SCENARIO_AS_NO_DAA, RA_HASH_ALG_SHA256, nil}
	inparam := provisionInParam{RAProvisionInHandler, inpayload}
	inparamjson, err := json.Marshal(inparam)
	if err != nil {
		log.Printf("Encode NoDAA json message error, %v", err)
		return nil, err
	}

	/*** format conversion: Go -> C ***/
	// in parameter conversion
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(inparamjson))
	up_c_in := C.CBytes(inparamjson)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	c_out := C.struct_ra_buffer_data{}
	c_out.size = 0x3000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))

	result := C.RemoteAttest(&c_in, &c_out)
	if result != 0 {
		return nil, errors.New("invoke remoteAttest failed")
	}
	akcertByte := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))
	/*
		err = createFile("path", akcertByte)
		if err != nil{
			return nil, errors.New("invoke remoteAttest failed")
		}
	*/
	return akcertByte, nil
}

func createFile(path string, con []byte) error {
	f, err := os.Create(path)
	if err != nil {
		log.Print("Create AKCert(test) file failed!")
		return err
	}
	_, err1 := f.Write(con)
	if err1 != nil {
		log.Print("Write AKCert(test) to file failed!")
		return err1
	}
	err2 := f.Close()
	if err2 != nil {
		return err2
	}
	return nil
}

func provisionDAA() ([]byte, error) {
	in_curve := RA_DAA_CURVE_FP512BN
	inpayload := provisionInPl{RA_VERSION, RA_SCENARIO_AS_WITH_DAA, RA_HASH_ALG_SHA256, &in_curve}
	inparam := provisionInParam{RAProvisionInHandler, inpayload}
	inparamjson, err := json.Marshal(inparam)
	if err != nil {
		log.Printf("Encode DAA json message error, %v", err)
		return nil, err
	}

	/*** format conversion: Go -> C ***/
	// in parameter conversion
	c_in := C.struct_ra_buffer_data{}
	c_in.size = C.__uint32_t(len(inparamjson))
	up_c_in := C.CBytes(inparamjson)
	c_in.buf = (*C.uchar)(up_c_in)
	defer C.free(up_c_in)

	c_out := C.struct_ra_buffer_data{}
	c_out.size = 0x3000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))

	result := C.RemoteAttest(&c_in, &c_out)
	if result != 0 {
		return nil, errors.New("invoke remoteAttest failed")
	}

	akcertByte := []byte(C.GoBytes(unsafe.Pointer(c_out.buf), C.int(c_out.size)))

	return akcertByte, nil
}

/*
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
*/

// GenerateAKCert generates ak cert according to qca server scenario configuration.
func GenerateAKCert() ([]byte, error) {
	switch Qcacfg.Scenario {
	case typeConv(RA_SCENARIO_NO_AS):
		result, err := provisionNoAS()
		if err != nil {
			log.Print("NoAS scenario: Generate RSA AK and AK Cert failed!")
			return nil, err
		}
		if result != 0 {
			log.Print("NoAS scenario: Generate RSA AK and AK Cert failed!")
		} else {
			log.Print("NoAS scenario: Generate RSA AK and AK Cert succeeded!")
		}
	case typeConv(RA_SCENARIO_AS_NO_DAA):
		akcert, err := provisionNoDAA()
		if err != nil {
			log.Print("NoDAA scenario: Generate RSA AK and AK Cert failed!")
			return nil, err
		}
		log.Print("NoDAA scenario: Generate RSA AK and AK Cert succeeded!")
		return akcert, nil
	case typeConv(RA_SCENARIO_AS_WITH_DAA):
		akcert, err := provisionDAA()
		if err != nil {
			log.Print("DAA scenario: Generate AK and AK Cert failed!")
			return nil, err
		}
		log.Print("DAA scenario: Generate AK and AK Cert succeeded!")
		return akcert, nil
	default:
		return nil, errors.New("scenario is not supported yet")
	}
	return nil, errors.New("do not need to access as")
}

// SaveAKCert saves ak cert to the specified file.
func SaveAKCert(cert []byte) error {
	cert_buf := C.CBytes(cert)
	cert_data := C.struct_ra_buffer_data{0, (*C.uchar)(cert_buf)}
	cert_data.size = C.__uint32_t(len(cert))
	defer C.free(cert_buf)

	c_out := C.struct_ra_buffer_data{}
	c_out.size = 0x3000
	c_out.buf = (*C.uint8_t)(C.malloc(C.ulong(c_out.size)))

	result := C.RemoteAttest(&cert_data, &c_out)
	if result != 0 {
		log.Print("Save AK Cert failed!")
		return errors.New("invoke RemoteAttest failed")
	}
	return nil
}
