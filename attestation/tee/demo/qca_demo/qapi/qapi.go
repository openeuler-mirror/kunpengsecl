// An interface provided to attester
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
	RA_SCENARIO_NO_AS = int32(iota)
	RA_SCENARIO_AS_NO_DAA
	RA_SCENARIO_AS_WITH_DAA
)

var (
	count int = 0
	l     sync.Mutex
)

func (s *service) GetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error) {
	countConnections()
	_ = ctx // ignore the unused warning
	Usrdata := in.GetNonce()
	rep := qcatools.GetTAReport(in.GetUuid(), Usrdata, in.WithTcb)
	rpy := GetReportReply{
		TeeReport: rep,
	}
	return &rpy, nil
}

func StartServer() {
	log.Print("Start Server......")
	listen, err := net.Listen("tcp", qcatools.Qcacfg.Server)
	if err != nil {
		log.Fatalf("Listen %s failed, err: %v\n", qcatools.Qcacfg.Server, err)
		return
	}

	s := grpc.NewServer()
	RegisterQcaServer(s, &service{})

	result := hasAKCert(qcatools.Qcacfg.Scenario)
	if !result {
		createAKCert(qcatools.Qcacfg.Scenario)
	}

	if err = s.Serve(listen); err != nil {
		log.Fatalf("Server: fail to serve %v", err)
	}

	log.Print("Stop Server......")
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
	newCert, err := aslib.GetAKCert(ac, s)
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
}

func createFile(path string, con []byte) error {
	f, err := os.Create(path)
	if err != nil {
		log.Print("Create AKCert file failed!")
		return err
	}
	_, err = f.Write(con)
	if err != nil {
		log.Print("Write AKCert to file failed!")
		return err
	}
	f.Close()
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
