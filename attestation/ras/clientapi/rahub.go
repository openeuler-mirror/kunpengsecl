/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3
Create: 2021-11-16
Description: Using leverage clientapi to implement a hub.
*/

package clientapi

import (
	"context"

	"log"
	"net"
	"sync"

	"google.golang.org/grpc"
)

type rahub struct {
	UnimplementedRasServer
	sync.Mutex
	rasAddr string
}

func (s *rahub) GenerateEKCert(ctx context.Context, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	log.Printf("rahub: receive GenerateEKCert")
	return DoGenerateEKCert(s.rasAddr, in)
}

func (s *rahub) GenerateIKCert(ctx context.Context, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	log.Printf("rahub: receive GenerateIKCert")
	return DoGenerateIKCert(s.rasAddr, in)
}

func (s *rahub) RegisterClient(ctx context.Context, in *RegisterClientRequest) (*RegisterClientReply, error) {
	log.Printf("rahub: receive RegisterClient")
	return DoRegisterClient(s.rasAddr, in)
}

func (s *rahub) UnregisterClient(ctx context.Context, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	log.Printf("rahub: receive UnregisterClient")
	return DoUnregisterClient(s.rasAddr, in)
}

func (s *rahub) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	log.Printf("rahub: receive SendHeartbeat")
	return DoSendHeartbeat(s.rasAddr, in)
}

func (s *rahub) SendReport(ctx context.Context, in *SendReportRequest) (*SendReportReply, error) {
	log.Printf("rahub: receive SendReport")
	return DoSendReport(s.rasAddr, in)
}

// StartServer starts ras server and provides rpc services.
func StartRaHub(addr, rasAddr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("rahub: fail to listen at %v", err)
		return
	}
	s := grpc.NewServer()
	svc := &rahub{rasAddr: rasAddr}
	RegisterRasServer(s, svc)
	log.Printf("rahub: listen at %s", addr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("rahub: fail to serve %v", err)
	}
}
