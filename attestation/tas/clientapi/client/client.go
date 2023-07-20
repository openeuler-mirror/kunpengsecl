/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wanghaijing
Create: 2023-07-17
Description: Using grpc to implement the service API, for client to use
*/

package client

import (
	"context"
	"errors"
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"google.golang.org/grpc"
)

type (
	tasConn struct {
		ctx    context.Context
		cancel context.CancelFunc
		conn   *grpc.ClientConn
		c      clientapi.TasClient
	}
)

func makesock(addr string) (*tasConn, error) {
	tas := &tasConn{}
	tas.ctx, tas.cancel = context.WithTimeout(context.Background(), 60*time.Second)
	conn, err := grpc.DialContext(tas.ctx, addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, errors.New("Client: fail to connect " + addr)
	}
	tas.conn = conn
	tas.c = clientapi.NewTasClient(conn)
	log.Printf("Client: connect to %s", addr)
	return tas, nil
}

// DoGetAKCert using existing tee ak service connection to get ak cert.
func DoGetAKCert(addr string, in *clientapi.GetAKCertRequest) (*clientapi.GetAKCertReply, error) {
	tas, err := makesock(addr)
	if err != nil {
		return nil, err
	}
	defer tas.conn.Close()
	defer tas.cancel()

	rpy, err := tas.c.GetAKCert(tas.ctx, in)
	if err != nil {
		return nil, err
	}
	return rpy, nil
}
