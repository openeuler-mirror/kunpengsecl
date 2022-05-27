// invoke qca lib to get info of given TA
package qcatools

/*
#cgo CFLAGS: -I../../../tverlib/simulator
#cgo LDFLAGS: -L${SRCDIR}/../../../tverlib/simulator -lteeqca -Wl,-rpath=${SRCDIR}/../../../tverlib/simulator
#include "../../../tverlib/simulator/teeqca.h"

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
	"net"
	"time"
	"unsafe"

	"github.com/spf13/viper"
)

const (
	ConfName = "config"
	ConfExt  = "yaml"
	strPath  = "."
	Server   = "qcaconfig.server"
)

type (
	Go_ra_buffer_data struct {
		Size uint32
		Buf  []uint8
	}
	qcaConfig struct {
		server string
	}
)

var (
	// store C data which convert from Go
	c_ta_uuid   C.TEEC_UUID = C.TEEC_UUID{}
	c_usr_data  C.struct_ra_buffer_data = C.struct_ra_buffer_data{}
	c_param_set C.struct_ra_buffer_data = C.struct_ra_buffer_data{}
	c_report    C.struct_ra_buffer_data = C.struct_ra_buffer_data{}
	c_with_tcb  C.bool

	// store TEEC_Result return from qcalib
	teec_result C.TEEC_Result

	// used for pointer conversion between Go and C
	up_usr_data_buf  unsafe.Pointer
	up_param_set_buf unsafe.Pointer
	up_report_buf    unsafe.Pointer

	// Store Go data transfer to C
	Usrdata  []byte = []byte{}
	Paramset []byte = []byte{}
	Report   []byte = make([]byte, 8192)

	// server side config
	qcacfg       *qcaConfig = nil
	defaultPaths            = []string{
		strPath,
	}

	// nonce value for defending against replay attacks
	nonce []byte
)

func LoadConfigs() {
	if qcacfg != nil {
		return
	}
	qcacfg = &qcaConfig{}
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
	qcacfg.server = viper.GetString(Server)
}

func GetTAReport(ta_uuid []byte, usr_data []byte, with_tcb bool) ([]byte) {
	// format conversion: Go -> C
	c_ta_uuid := C.CBytes(ta_uuid) 
	defer C.free(c_ta_uuid)

	c_usr_data.size = C.__uint32_t(len(usr_data))
	up_usr_data_buf = C.CBytes(usr_data)
	c_usr_data.buf = (*C.uchar)(up_usr_data_buf)
	defer C.free(up_usr_data_buf)

	c_param_set := C.struct_ra_buffer_data{}
	c_param_set.buf = C.generateParamSetBuffer()
	c_param_set.size = C.getParamSetBufferSize(c_param_set.buf)
	defer C.free(unsafe.Pointer(c_param_set.buf))

	// c_param_set.size = C.__uint32_t(param_set.Size)
	// up_param_set_buf = C.CBytes(param_set.Buf)
	//c_param_set.buf = (*C.uchar)(up_param_set_buf)
	// defer C.free(up_param_set_buf)

	c_report.size = C.__uint32_t(len(Report))
	up_report_buf = C.CBytes(Report)
	c_report.buf = (*C.uchar)(up_report_buf)
	defer C.free(up_report_buf)

	c_with_tcb = C.bool(with_tcb)

	teec_result = C.RemoteAttestReport(*(*C.TEEC_UUID)(c_ta_uuid), &c_usr_data, &c_param_set, &c_report, c_with_tcb) // can not put Go pointer as parameter in C function!!!
	if int(teec_result) != 0 {
		log.Print("Get TA report failed!")
		return nil
	}

	// format conversion: C -> Go
	Report = []uint8(C.GoBytes(unsafe.Pointer(c_report.buf), C.int(c_report.size)))

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
	c_out.size = 0
	result := C.RemoteAttestProvision(0, &c_param_set, &c_out)
	C.free(unsafe.Pointer(c_param_set.buf))
	return int(result)
}

func handleConnection(c net.Conn) {
	result := provisionNoAS()
	if result == 0 {
		log.Print("Generate RSA AK and AK Cert failed!")
		return
	}
	c.Close()
}

func StartServer() {
	log.Print("Start Server......")
	listen, err := net.Listen("tcp", qcacfg.server)
	if err != nil {
		log.Printf("Listen %s failed, err: %v\n", qcacfg.server, err)
		return
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("Accept connection failed: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if conn != nil {
			log.Printf("Connection %s success!", qcacfg.server)

			handleConnection(conn)
			break
		}
	}

	log.Print("Stop Server......")
}
