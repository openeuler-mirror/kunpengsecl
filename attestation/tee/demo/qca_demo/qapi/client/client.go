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
Description: An interface provided to attester, for client to use
*/

package client

import (
	"context"
	"errors"
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"google.golang.org/grpc"
)

type (
	qcaConn struct {
		ctx    context.Context
		cancel context.CancelFunc
		conn   *grpc.ClientConn
		c      qapi.QcaClient
	}
)

func makesock(addr string) (*qcaConn, error) {
	qca := &qcaConn{}
	// If the client is not connected to the server within 3 seconds, an error is returned!
	qca.ctx, qca.cancel = context.WithTimeout(context.Background(), 60*time.Second)
	conn, err := grpc.DialContext(qca.ctx, addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, errors.New("Client: fail to connect " + addr)
	}
	qca.conn = conn
	qca.c = qapi.NewQcaClient(conn)
	log.Printf("Client: connect to %s", addr)
	return qca, nil
}

// DoGetTeeReport using existing qca demo connection to get tee report.
func DoGetTeeReport(addr string, in *qapi.GetReportRequest) (*qapi.GetReportReply, error) {
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
