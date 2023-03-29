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
Description: An interface provided to attester
*/

package qapi

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/aslib"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
	grpc "google.golang.org/grpc"
)

type (
	service struct {
		UnimplementedQcaServer
	}
	qcaConn struct {
		ctx    context.Context
		cancel context.CancelFunc
		conn   *grpc.ClientConn
		c      QcaClient
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
func (s *service) GetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error) {
	countConnections()
	_ = ctx // ignore the unused warning
	Usrdata := in.GetNonce()
	rep, err := qcatools.GetTAReport(in.GetUuid(), Usrdata, in.WithTcb)
	if err != nil {
		log.Print("Get TA Report failed!")
		return nil, err
	}
	rpy := GetReportReply{
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
	RegisterQcaServer(srv, &service{})

	result := hasAKCert(qcatools.Qcacfg.Scenario)
	if !result {
		createAKCert(qcatools.Qcacfg.Scenario)
	}

	if err = srv.Serve(listen); err != nil {
		log.Fatalf("Server: fail to serve %v", err)
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

func makesock(addr string) (*qcaConn, error) {
	qca := &qcaConn{}
	// If the client is not connected to the server within 3 seconds, an error is returned!
	qca.ctx, qca.cancel = context.WithTimeout(context.Background(), 60*time.Second)
	conn, err := grpc.DialContext(qca.ctx, addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, errors.New("Client: fail to connect " + addr)
	}
	qca.conn = conn
	qca.c = NewQcaClient(conn)
	log.Printf("Client: connect to %s", addr)
	return qca, nil
}

// DoGetTeeReport using existingqca demo connection to get tee report.
func DoGetTeeReport(addr string, in *GetReportRequest) (*GetReportReply, error) {
	qca, err := makesock(addr)
	if err != nil {
		return nil, err
	}
	defer qca.conn.Close()
	defer qca.cancel()

	rpy, err := qca.c.GetReport(qca.ctx, in)
	if err != nil {
		return nil, err
	}

	return rpy, nil
}
