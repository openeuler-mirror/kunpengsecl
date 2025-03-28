/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-10-08
Description: Using grpc to implement the rasService API.
	1. 2022-01-19	wucaijun
		redefine SendReportRequest parameters and refine some implementations.
	2. 2022-01-28	wucaijun
		fix the problem that grpc occupy all the file handle, use LimitListener
		and getSockNum to auto adjust the max limit of grpc socket handle.
	3. 2022-01-29	wucaijun
		add a new group communication functions to rac, these functions will try
	to use the same grpc socket to enhance performance if possible.

Notice:
	For performance, change the process max file limit and database max connections.
`ulimit -n 200000`			# set in the ras start bash script
`max_connections = 1000`	# in /var/lib/pgsql/data/postgresql.conf and restart
*/

// clientapi package implements the grpc communication between rac and ras.
package client

import (
	"context"
	"errors"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"google.golang.org/grpc"
)

const (
	constTimeOut time.Duration = 20 * time.Second
)

var (
	// ErrClientApiParameterWrong means client api parameter wrong error
	ErrClientApiParameterWrong = errors.New("client api parameter wrong")
)

// RasConn means ras connection information
type RasConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   *grpc.ClientConn
	c      clientapi.RasClient
}

// CreateConn creates a grpc connection to remote server at addr:ip.
func CreateConn(addr string) (*RasConn, error) {
	ras := &RasConn{}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.FailOnNonTempDialError(true))
	if err != nil {
		logger.L.Sugar().Errorf("connect %s error, %v", addr, err)
		return nil, typdefs.ErrConnectFailed
	}
	ras.conn = conn
	ras.c = clientapi.NewRasClient(conn)
	ras.ctx, ras.cancel = context.WithTimeout(context.Background(), constTimeOut)
	return ras, nil
}

// ReleaseConn releases the ras connection.
func ReleaseConn(ras *RasConn) {
	if ras != nil {
		ras.cancel()
		ras.conn.Close()
	}
}

// DoGenerateEKCertWithConn uses existing ras connection to generate an ek certificate from ras server for client.
func DoGenerateEKCertWithConn(ras *RasConn, in *clientapi.GenerateEKCertRequest) (*clientapi.GenerateEKCertReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.GenerateEKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateEKCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoGenerateIKCertWithConn uses existing ras connection to generate an identity certificate from ras server for client.
func DoGenerateIKCertWithConn(ras *RasConn, in *clientapi.GenerateIKCertRequest) (*clientapi.GenerateIKCertReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.GenerateIKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateIKCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoRegisterClientWithConn uses existing ras connection to register the rac to the ras server.
func DoRegisterClientWithConn(ras *RasConn, in *clientapi.RegisterClientRequest) (*clientapi.RegisterClientReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.RegisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke RegisterClient error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoUnregisterClientWithConn uses existing ras connection to unregister the rac from the ras server.
func DoUnregisterClientWithConn(ras *RasConn, in *clientapi.UnregisterClientRequest) (*clientapi.UnregisterClientReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.UnregisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke UnregisterClient error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendHeartbeatWithConn uses existing ras connection to send a heart beat message to the ras server.
func DoSendHeartbeatWithConn(ras *RasConn, in *clientapi.SendHeartbeatRequest) (*clientapi.SendHeartbeatReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.SendHeartbeat(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendHeartbeat error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendReportWithConn uses existing ras connection to send a trust report message to the ras server.
func DoSendReportWithConn(ras *RasConn, in *clientapi.SendReportRequest) (*clientapi.SendReportReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.SendReport(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendReport error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendKCMPubKeyCertWithConn uses existing ras connection to send kcm public key cert from the ras server.
func DoSendKCMPubKeyCertWithConn(ras *RasConn, in *clientapi.SendKCMPubKeyCertRequest) (*clientapi.SendKCMPubKeyCertReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.SendKCMPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendKCMPubKeyCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoVerifyKTAPubKeyCertWithConn uses existing ras connection to verify kta public key cert to the ras server.
func DoVerifyKTAPubKeyCertWithConn(ras *RasConn, in *clientapi.VerifyKTAPubKeyCertRequest) (*clientapi.VerifyKTAPubKeyCertReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.VerifyKTAPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke VerifyKTAPubKeyCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoKeyOperationWithConn uses existing ras connection to handle key operation.
func DoKeyOperationWithConn(ras *RasConn, in *clientapi.KeyOperationRequest) (*clientapi.KeyOperationReply, error) {
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.KeyOperation(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke KeyOperation error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoGenerateEKCert generates an ek certificate from ras server for client.
func DoGenerateEKCert(addr string, in *clientapi.GenerateEKCertRequest) (*clientapi.GenerateEKCertReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.GenerateEKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateEKCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoGenerateIKCert generates an identity certificate from ras server for client.
func DoGenerateIKCert(addr string, in *clientapi.GenerateIKCertRequest) (*clientapi.GenerateIKCertReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.GenerateIKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateIKCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoRegisterClient registers the rac to the ras server.
func DoRegisterClient(addr string, in *clientapi.RegisterClientRequest) (*clientapi.RegisterClientReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.RegisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke RegisterClient error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoUnregisterClient unregisters the rac from the ras server.
func DoUnregisterClient(addr string, in *clientapi.UnregisterClientRequest) (*clientapi.UnregisterClientReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.UnregisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke UnregisterClient error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendHeartbeat sends a heart beat message to the ras server.
func DoSendHeartbeat(addr string, in *clientapi.SendHeartbeatRequest) (*clientapi.SendHeartbeatReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendHeartbeat(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendHeartbeat error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendReport sends a trust report message to the ras server.
func DoSendReport(addr string, in *clientapi.SendReportRequest) (*clientapi.SendReportReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendReport(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendReport error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoSendKCMPubKeyCert sends kcm public key cert from the ras server.
func DoSendKCMPubKeyCert(addr string, in *clientapi.SendKCMPubKeyCertRequest) (*clientapi.SendKCMPubKeyCertReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.SendKCMPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendKCMPubKeyCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoVerifyKTAPubKeyCert verifies kta public key cert to the ras server.
func DoVerifyKTAPubKeyCert(addr string, in *clientapi.VerifyKTAPubKeyCertRequest) (*clientapi.VerifyKTAPubKeyCertReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.VerifyKTAPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke VerifyKTAPubKeyCert error, %v", err)
		return nil, err
	}
	return bk, nil
}

// DoKeyOperation handles key operations,
// such as generate new key, get key and delete key.
func DoKeyOperation(addr string, in *clientapi.KeyOperationRequest) (*clientapi.KeyOperationReply, error) {
	ras, err := CreateConn(addr)
	if err != nil {
		return nil, err
	}
	defer ras.conn.Close()
	defer ras.cancel()

	bk, err := ras.c.KeyOperation(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke KeyOperation error, %v", err)
		return nil, err
	}
	return bk, nil
}
