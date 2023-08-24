/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-04-20
Description: An interface provided to attester, for server to use
*/

package server

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/aslib"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
	"google.golang.org/grpc"
)

type (
	service struct {
		qapi.UnimplementedQcaServer
	}
)

const (
	// app scenario
	// RA_SCENARIO_NO_AS means ra scenario without as
	RA_SCENARIO_NO_AS = int32(iota)
	// RA_SCENARIO_AS_NO_DAA means ra scenario as without daa
	RA_SCENARIO_AS_NO_DAA
	// RA_SCENARIO_AS_WITH_DAA means ra scenario as with daa
	RA_SCENARIO_AS_WITH_DAA
)

var (
	count int = 0
	l     sync.Mutex
	srv   *grpc.Server = nil
)

// GetReport gets report from report request.
func (s *service) GetReport(ctx context.Context, in *qapi.GetReportRequest) (*qapi.GetReportReply, error) {
	countConnections()
	_ = ctx // ignore the unused warning
	Usrdata := in.GetNonce()
	rep, err := qcatools.GetTAReport(in.GetUuid(), Usrdata, in.WithTcb)
	if err != nil {
		log.Print("Get TA Report failed!")
		return nil, err
	}
	rpy := qapi.GetReportReply{
		TeeReport: rep,
	}
	return &rpy, nil
}

// StartServer starts a server to start qca demo.
func StartServer() {
	log.Print("Start Server......")
	listen, err := net.Listen("tcp", qcatools.Qcacfg.Server)
	if err != nil {
		log.Fatalf("Listen %s failed, err: %v\n", qcatools.Qcacfg.Server, err)
		return
	}

	srv = grpc.NewServer()
	qapi.RegisterQcaServer(srv, &service{})

	result := hasAKCert(qcatools.Qcacfg.Scenario)
	if !result {
		createAKCert(qcatools.Qcacfg.Scenario)
	}

	if err = srv.Serve(listen); err != nil {
		log.Fatalf("Server: fail to serve %v", err)
                StopServer()
		return
	}

	log.Print("Stop Server......")
}

// StopServer stops the qca demo.
func StopServer() {
	if srv == nil {
		return
	}
	srv.Stop()
	srv = nil
}

func hasAKCert(s int32) bool {
	switch s {
	case RA_SCENARIO_NO_AS:
		log.Print("Serve in scenario: RA_SCENARIO_NO_AS")
		return false
	case RA_SCENARIO_AS_NO_DAA:
		log.Print("Serve in scenario: RA_SCENARIO_AS_NO_DAA")
		err := readFile(qcatools.Qcacfg.NoDaaACFile)
		if err != nil {
			return false
		}
	case RA_SCENARIO_AS_WITH_DAA:
		log.Print("Serve in scenario: RA_SCENARIO_AS_WITH_DAA")
		err := readFile(qcatools.Qcacfg.DaaACFile)
		if err != nil {
			return false
		}
	}
	return true
}

func readFile(path string) error {
	ac, err := ioutil.ReadFile(path)
	if err != nil {
		log.Print("AKCert File does not exist!")
		return err
	}
	if len(ac) == 0 {
		log.Print("Empty AKCert file!")
		return err
	}
	return nil
}

func createAKCert(s int32) {
	ac, err := qcatools.GenerateAKCert()
	if err != nil {
		return
	}
	newCert, err := aslib.GetAKCert(qcatools.Qcacfg.AKServer, ac, s)
	if err != nil {
		return
	}
	log.Print("Get new cert signed by as succeeded.")
	switch s {
	case RA_SCENARIO_AS_NO_DAA:
		err := createFile(qcatools.Qcacfg.NoDaaACFile, newCert)
		if err != nil {
			return
		}
	case RA_SCENARIO_AS_WITH_DAA:
		err := createFile(qcatools.Qcacfg.DaaACFile, newCert)
		if err != nil {
			return
		}
	}

	qcatools.SaveAKCert(newCert)
	log.Print("Save ak cert into tee.")
}

func createFile(path string, con []byte) error {
	f, err := os.Create(path)
	if err != nil {
		log.Print("Create AKCert file failed!")
		return err
	}
	_, err1 := f.Write(con)
	if err1 != nil {
		log.Print("Write AKCert to file failed!")
		return err1
	}
	err2 := f.Close()
	if err2 != nil {
		return err2
	}
	return nil
}

func countConnections() {
	l.Lock()
	count++
	l.Unlock()
	log.Printf("Now have %d clients connected to server", count)
}
