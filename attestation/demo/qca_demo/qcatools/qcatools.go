// invoke qca lib to get info of given TA
package qcatools

/*
#include <stdio.h>

#define uid 1;
#define quoted "test quoted";
#define sig "test signature";
#define c "test cert";
#define manifest "test manifest";

typedef struct
{
    __int64_t uuid;
    char* Quoted;
    char* Signature;
    char* cert;
    char* Manifest;
} TestReport;

TestReport GetInfo(char *id) {
    TestReport report;
    printf("Get Infomation to %s\n", id);
    report.uuid = uid;
    report.Quoted = quoted;
    report.Signature = sig;
    report.cert = c;
    report.Manifest = manifest;
    return report;
}
*/
import "C"

import (
	"log"
	"net"
	"time"
)

const (
// address = "127.0.0.1:40001"
)

var (
	address string = "127.0.0.1:40001"
)

type (
	testReport struct {
		Uuid      int64
		Quoted    string
		Signature string
		Cert      string
		Manifest  string
	}
)

func GetInfo(id string) testReport {
	var ti testReport
	ci := C.CString(id)
	// You need to release ci in a timely manner; otherwise, memory leaks may occur!!!
	// defer C.free(unsafe.Pointer(ci))
	info := C.GetInfo(ci)
	ti.Uuid = int64(info.uuid)
	ti.Quoted = C.GoString(info.Quoted)
	ti.Signature = C.GoString(info.Signature)
	ti.Cert = C.GoString(info.cert)
	ti.Manifest = C.GoString(info.Manifest)
	return ti
}

func handleConnection(c net.Conn) {
	log.Printf("Do next action with %v", c)
	c.Close()
}

func StartServer() {
	log.Print("Start Server......")
	listen, err := net.Listen("tcp", address)
	if err != nil {
		log.Printf("Listen %s failed, err: %v\n", address, err)
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
			log.Printf("Connection %s success!", address)

			handleConnection(conn)
			break
		}
	}

	log.Print("Stop Server......")
}
