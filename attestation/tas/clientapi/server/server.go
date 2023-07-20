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
Create: 2023-07-19
Description: Using grpc to implement the service API, for server to use
*/

package server

import (
	"context"
	"log"
	"net"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/akissuer"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"google.golang.org/grpc"
)

type (
	service struct {
		clientapi.UnimplementedTasServer
	}
)

var (
	akServer *grpc.Server
)

// StartServer starts a server to provide tee ak services.
func StartServer(addr string) {
	log.Print("Start tee ak server...")
	listen, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server: fail to listen at %s, %v", addr, err)
	}
	akServer = grpc.NewServer()
	clientapi.RegisterTasServer(akServer, &service{})
	if err := akServer.Serve(listen); err != nil {
		log.Fatalf("Server: fail to serve, %v", err)
	}
}

// StopServer stops the tee ak server.
func StopServer() {
	if akServer == nil {
		return
	}
	akServer.Stop()
	akServer = nil
}

// GetAKCert generates ak cert according to ak cert request
// and returns ak cert as reply.
func (s *service) GetAKCert(ctx context.Context, in *clientapi.GetAKCertRequest) (*clientapi.GetAKCertReply, error) {
	akcert, err := akissuer.GenerateAKCert(in.Akcert, in.Scenario)
	if err != nil {
		return nil, err
	}
	return &clientapi.GetAKCertReply{Akcert: akcert}, nil
}
