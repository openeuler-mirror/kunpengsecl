// invoke qca lib to get info of given TA
package qcatools

/*
#include "../../../tverlib/simulator/qcalib.h"
#include "../../../tverlib/simulator/qcalib.c"
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
	c_ta_uuid   C.__int64_t
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
	Usrdata  *Go_ra_buffer_data = &Go_ra_buffer_data{}
	Paramset *Go_ra_buffer_data = &Go_ra_buffer_data{}
	Report   *Go_ra_buffer_data = &Go_ra_buffer_data{}

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

func GetTAReport(ta_uuid int64, usr_data *Go_ra_buffer_data, param_set *Go_ra_buffer_data, report *Go_ra_buffer_data, with_tcb bool) (*Go_ra_buffer_data, []byte) {
	// format conversion: Go -> C
	c_ta_uuid = C.__int64_t(ta_uuid)

	c_usr_data.size = C.__uint32_t(usr_data.Size)
	up_usr_data_buf = C.CBytes(usr_data.Buf)
	c_usr_data.buf = (*C.uchar)(up_usr_data_buf)
	defer C.free(up_usr_data_buf)

	c_param_set.size = C.__uint32_t(param_set.Size)
	up_param_set_buf = C.CBytes(param_set.Buf)
	c_param_set.buf = (*C.uchar)(up_param_set_buf)
	defer C.free(up_param_set_buf)

	c_report.size = C.__uint32_t(report.Size)
	up_report_buf = C.CBytes(report.Buf)
	c_report.buf = (*C.uchar)(up_report_buf)
	defer C.free(up_report_buf)

	c_with_tcb = C.bool(with_tcb)

	teec_result = C.RemoteAttestReport(c_ta_uuid, &c_usr_data, &c_param_set, &c_report, c_with_tcb) // can not put Go pointer as parameter in C function!!!
	if int(teec_result) == 0 {
		log.Print("Get TA report failed!")
		return nil, nil
	}

	// format conversion: C -> Go
	report.Size = uint32(c_report.size)
	report.Buf = []uint8(C.GoBytes(unsafe.Pointer(c_report.buf), C.int(report.Size)))

	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(report.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, report.Buf[i])
	// }

	nonce = append(nonce, usr_data.Buf...)

	return report, nonce
}

func handleConnection(c net.Conn) {
	result := C.RemoteAttestProvision(0, nil, nil)
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
