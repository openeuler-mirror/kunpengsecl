// An interface provided to attester
package qapi

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

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

	qcatools.HandleConnection()

	if err = s.Serve(listen); err != nil {
		log.Fatalf("Server: fail to serve %v", err)
	}

	log.Print("Stop Server......")
}

func countConnections() {
	l.Lock()
	defer l.Unlock()
	count++
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
