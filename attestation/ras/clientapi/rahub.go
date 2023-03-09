/*
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
	"os"

	"net"
	"sync"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"google.golang.org/grpc"
)

type rahub struct {
	UnimplementedRasServer
	sync.Mutex
	rasAddr string
}

// GenerateEKCert returns ek cert.
func (s *rahub) GenerateEKCert(ctx context.Context, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	logger.L.Debug("rahub: receive GenerateEKCert")
	return DoGenerateEKCert(s.rasAddr, in)
}

// GenerateIKCert returns ik cert.
func (s *rahub) GenerateIKCert(ctx context.Context, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	logger.L.Debug("rahub: receive GenerateIKCert")
	return DoGenerateIKCert(s.rasAddr, in)
}

// RegisterClient creates a new client in database.
func (s *rahub) RegisterClient(ctx context.Context, in *RegisterClientRequest) (*RegisterClientReply, error) {
	logger.L.Debug("rahub: receive RegisterClient")
	return DoRegisterClient(s.rasAddr, in)
}

// UnregisterClient unregisters client
// by setting client's registration status to false.
func (s *rahub) UnregisterClient(ctx context.Context, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	logger.L.Debug("rahub: receive UnregisterClient")
	return DoUnregisterClient(s.rasAddr, in)
}

// SendHeartbeat sends a heart beat message to the ras server.
func (s *rahub) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	logger.L.Debug("rahub: receive SendHeartbeat")
	return DoSendHeartbeat(s.rasAddr, in)
}

// SendReport sends a trust report message to the ras server.
func (s *rahub) SendReport(ctx context.Context, in *SendReportRequest) (*SendReportReply, error) {
	logger.L.Debug("rahub: receive SendReport")
	return DoSendReport(s.rasAddr, in)
}

// StartRaHub starts ras server and provides rpc services.
func StartRaHub(addr, rasAddr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.L.Sugar().Fatalf("rahub: fail to listen at %v", err)
		os.Exit(1)
	}
	s := grpc.NewServer()
	svc := &rahub{rasAddr: rasAddr}
	RegisterRasServer(s, svc)
	logger.L.Sugar().Debugf("rahub: listen at %s", addr)
	if err := s.Serve(lis); err != nil {
		logger.L.Sugar().Errorf("rahub: fail to serve %v", err)
	}
}
