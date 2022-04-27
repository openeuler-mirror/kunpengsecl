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
		Buf  []byte
	}
	qcaConfig struct {
		server string
	}
)

var (
	c_ra_buffer_data C.ra_buffer_data
	c_ta_uuid        C.__int64_t
	c_usr_data       C.ra_buffer_data
	c_report         C.ra_buffer_data
	c_with_tcb       C.bool
	str_usrdata_buf  string
	str_report_buf   string
	go_report        *Go_ra_buffer_data = &Go_ra_buffer_data{}
	qcacfg           *qcaConfig         = nil
	defaultPaths                        = []string{
		strPath,
	}
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

func GetTAReport(ta_uuid int64, usr_data *Go_ra_buffer_data, report *Go_ra_buffer_data, with_tcb bool) *Go_ra_buffer_data {
	// format conversion: Go -> C
	c_ta_uuid = C.__int64_t(ta_uuid)
	c_usr_data.size = C.__uint32_t(usr_data.Size)
	str_usrdata_buf = string(usr_data.Buf)
	c_usr_data.buf = (*C.uchar)(C.CString(str_usrdata_buf))
	c_report.size = C.__uint32_t(report.Size)
	str_report_buf = string(report.Buf)
	c_report.buf = (*C.uchar)(C.CString(str_report_buf))
	c_with_tcb = C.bool(with_tcb)

	c_ra_buffer_data = C.RemoteAttestReport(c_ta_uuid, &c_usr_data, &c_report, c_with_tcb) // can not put Go pointer as parameter in C function!!!

	// format conversion: C -> Go
	go_report.Size = uint32(c_ra_buffer_data.size)
	go_report.Buf = []byte(C.GoString((*C.char)(c_ra_buffer_data.buf))) // empty line has some impacts on output?

	return go_report
}

func handleConnection(c net.Conn) {
	log.Printf("Do next action with %v", c)
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
