// invoke attester lib and get info from qapi
package attestertools

/*
#include <stdio.h>

typedef struct
{
    __int64_t uuid;
    char* Quoted;
    char* Signature;
    char* cert;
    char* Manifest;
} TAreport;

typedef struct
{
    char* Mmem;
    char* Minit;
    char* Mimg;
} BaseValue;

void VerifySignature(TAreport *report) {
    printf("Verify success!\n");
}

void Validate(TAreport *manifest, BaseValue *basevalue) {
    printf("Validate success!\n");
}
*/
import "C"

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"gitee.com/openeuler/kunpengsecl/attestation/demo/qca_demo/qapi"
	"github.com/spf13/pflag"
)

const (
	// default config
	attesterVersion = "version 1.0.0"
	// address         = "127.0.0.1:40001"
	// version output
	lflagVersion = "version"
	sflagVersion = "V"
	helpVersion  = "show version number and quit"
	// connect test
	id        = "me"
	basevalue = "test basevalue"
)

var (
	VersionFlag *bool     = nil
	VerboseFlag *bool     = nil
	ta          *trustApp = nil
	address     string    = "127.0.0.1:40001"
)

type (
	trustApp struct {
		ctx context.Context
	}
	testReport struct {
		Uuid      int64
		Quoted    string
		Signature string
		Cert      string
		Manifest  string
	}
)

func InitFlags() {
	log.Print("Init flags......")
	VersionFlag = pflag.BoolP(lflagVersion, sflagVersion, false, helpVersion)
	pflag.Parse()
}

func HandleFlags() {
	log.Print("Handle flags......")
	if VersionFlag != nil && *VersionFlag {
		fmt.Printf("TEE Remote Attester: %s\n", attesterVersion)
		os.Exit(0)
	}
}

func StartAttester() {
	log.Print("Start Attester......")
	conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("Dial %s failed, err: %v", address, err)
		return
	}
	defer conn.Close()
	if conn != nil {
		log.Printf("Connection %s success!", address)
		info := getInfo(ta)
		verifySig(info)
		validate(info, basevalue)
	}

	log.Print("Stop Attester......")
}

// remote invoke qca api to get the TA's info
func getInfo(ta *trustApp) testReport {
	result := testReport{}
	reqID := qapi.GetInfoRequest{
		Identity: id,
	}

	rpyID, err := qapi.DoGetInfo(ta.ctx, &reqID)
	if err != nil {
		log.Printf("Get TA infomation failed, error: %v", err)
		return result
	}

	result = testReport{
		Uuid:      rpyID.GetUuid(),
		Quoted:    rpyID.GetQuoted(),
		Signature: rpyID.GetSignature(),
		Cert:      rpyID.GetCert(),
		Manifest:  rpyID.GetManifest(),
	}
	log.Printf("Get TA uuid success: %d\n", result.Uuid)
	log.Printf("Get TA quote success: %s\n", result.Quoted)
	log.Printf("Get TA signature success: %s\n", result.Signature)
	log.Printf("Get TA cert success: %s\n", result.Cert)
	log.Printf("Get TA manifest success: %s\n", result.Manifest)
	return result
}

// invoke verifier lib to verify
func verifySig(rep testReport) bool {
	var crep C.TAreport
	crep = extract(rep, crep)
	C.VerifySignature(&crep)
	return true
}

// convert report in Go to report in C
func extract(rep testReport, crep C.TAreport) C.TAreport {
	crep.uuid = C.__int64_t(rep.Uuid)
	cq := C.CString(rep.Quoted)
	cs := C.CString(rep.Signature)
	cc := C.CString(rep.Cert)
	cm := C.CString(rep.Manifest)
	crep.Quoted = cq
	crep.Signature = cs
	crep.cert = cc
	crep.Manifest = cm
	return crep
}

// invoke verifier lib to validate
func validate(mf testReport, bv string) bool {
	var crep C.TAreport
	var cbv C.BaseValue
	cbv.Mmem = C.CString(bv) // just for test
	crep = extract(mf, crep)
	C.Validate(&crep, &cbv)
	return true
}
