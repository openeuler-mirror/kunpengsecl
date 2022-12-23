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
package clientapi

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	kmsServer "gitee.com/openeuler/kunpengsecl/attestation/kms"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kcmstools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
)

const (
	constTimeOut time.Duration = 20 * time.Second

	strDbConfig  = "user=%s password=%s dbname=%s host=%s port=%d sslmode=disable"
	strSpaceLine = " \n\r"
	strGetName   = "./get.sh"
	strGetSh     = `#!/bin/bash
cat $1 | awk '/open files/ { print $4 }'`
)

const (
	constDB = "postgres"
)

var (
	certPath     = "../cert/"
	kcmFileName  = "kcm.crt"
	ktaFileName  = "kta.crt"
	rootFileName = "ca.crt"
	kcmKeyName   = "kcm.key"
)

// var Nonce []byte
//var privKey []byte
//var kcmPublicKey []byte

type rasService struct {
	UnimplementedRasServer
}

type tagCmdData struct {
	Key        []byte
	EncCmdData []byte
}

type inKeyInfo struct {
	TAId      []byte
	Account   []byte
	Password  []byte
	KeyId     []byte
	HostKeyId []byte
	Command   uint32
	KTAId     string
}

type retKeyInfo struct {
	TAId      []byte
	KeyId     []byte
	PlainText []byte
	HostKeyId []byte
}

var (
	ErrClientApiParameterWrong = errors.New("client api parameter wrong")

	srv *grpc.Server = nil
)

func getSockNum() int {
	pid := os.Getpid()
	limits := fmt.Sprintf("/proc/%d/limits", pid)
	ioutil.WriteFile(strGetName, []byte(strGetSh), 0755)
	out, _ := exec.Command(strGetName, limits).Output()
	totalStr := strings.Trim(string(out), strSpaceLine)
	totalNum, _ := strconv.Atoi(totalStr)
	sockNum := totalNum * 9 / 10
	if totalNum-sockNum < 50 {
		sockNum = totalNum - 50
	}
	os.Remove(strGetName)
	return sockNum
}

// newRasServer creates a new rasService to support clientapi interface.
func newRasService() *rasService {
	return &rasService{}
}

// StartServer starts a server to provide ras rpc services.
func StartServer(addr string) {
	var err error
	if srv != nil {
		return
	}
	if addr == "" {
		logger.L.Sugar().Errorf("listen ip:port can not be empty")
		return
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logger.L.Sugar().Errorf("fail to listen at %s, %v", addr, err)
		return
	}
	dbConfig := fmt.Sprintf(strDbConfig, config.GetDBUser(), config.GetDBPassword(),
		config.GetDBName(), config.GetDBHost(), config.GetDBPort())
	trustmgr.CreateTrustManager("postgres", dbConfig)
	srv := grpc.NewServer()
	RegisterRasServer(srv, newRasService())
	//logger.L.Sugar().Debugf("listen at %s", addr)
	lis = netutil.LimitListener(lis, getSockNum())
	err = srv.Serve(lis)
	if err != nil {
		logger.L.Sugar().Errorf("fail to serve, %v", err)
	}
}

// StopServer stops the server and trust manager, release all resources.
func StopServer() {
	if srv == nil {
		return
	}
	srv.Stop()
	srv = nil
	trustmgr.ReleaseTrustManager()
}

// GenerateEKCert handles the generation of the EK certificate for client.
func (s *rasService) GenerateEKCert(ctx context.Context, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	//logger.L.Debug("get GenerateEKCert request")
	t := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(cryptotools.GetSerialNumber()),
		NotBefore:    t,
		NotAfter:     t.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP(config.GetIP())},
	}
	ekCert, err := cryptotools.GenerateCertificate(&template,
		config.GetPcaKeyCert(), in.GetEkPub(), config.GetPcaPrivateKey())
	if err != nil {
		logger.L.Sugar().Errorf("generate EK Cert fail, %v", err)
		return nil, err
	}
	//logger.L.Debug("send GenerateEKCert reply")
	return &GenerateEKCertReply{EkCert: ekCert}, nil
}

// GenerateIKCert handles the generation of the IK certificate for client.
func (s *rasService) GenerateIKCert(ctx context.Context, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	//logger.L.Debug("get GenerateIKCert request")
	t := time.Now()
	template := x509.Certificate{
		SerialNumber: big.NewInt(cryptotools.GetSerialNumber()),
		NotBefore:    t,
		NotAfter:     t.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP(config.GetIP())},
	}
	ikCertDer, err := cryptotools.GenerateCertificate(&template,
		config.GetPcaKeyCert(), in.GetIkPub(), config.GetPcaPrivateKey())
	if err != nil {
		logger.L.Sugar().Errorf("generate IK Cert fail, %v", err)
		return nil, err
	}
	ekCert, err := x509.ParseCertificate(in.GetEkCert())
	if err != nil {
		logger.L.Sugar().Errorf("parse client EK Cert fail, %v", err)
		return nil, err
	}
	encIkCert, err := cryptotools.EncryptIKCert(ekCert.PublicKey,
		ikCertDer, in.GetIkName())
	if err != nil {
		logger.L.Sugar().Errorf("encrypt IK Cert with EK public key fail, %v", err)
		return nil, err
	}
	//logger.L.Debug("send GenerateIKCert reply")
	return &GenerateIKCertReply{
		EncryptedIC:     encIkCert.EncryptedCert,
		CredBlob:        encIkCert.SymKeyParams.CredBlob,
		EncryptedSecret: encIkCert.SymKeyParams.EncryptedSecret,
		EncryptAlg:      encIkCert.SymKeyParams.EncryptAlg,
		EncryptParam:    encIkCert.SymKeyParams.EncryptParam,
	}, nil
}

// RegisterClient registers a new client by IK certificate and its client information string.
func (s *rasService) RegisterClient(ctx context.Context, in *RegisterClientRequest) (*RegisterClientReply, error) {
	//logger.L.Debug("get RegisterClient request")
	registered := false
	if config.GetMgrStrategy() == config.AutoStrategy {
		registered = true
	}
	ikDer := in.GetCert()
	ikPem, err := cryptotools.EncodeKeyCertToPEM(ikDer)
	if err != nil {
		logger.L.Sugar().Errorf("encode IK Cert to PEM fail, %v", err)
		return &RegisterClientReply{ClientId: -1}, err
	}
	client, err := trustmgr.RegisterClientByIK(string(ikPem), in.GetClientInfo(), registered)
	if err != nil {
		logger.L.Sugar().Errorf("register client fail, %v", err)
		return &RegisterClientReply{ClientId: -1}, err
	}
	//logger.L.Sugar().Debugf("send RegisterClient reply, ClientID=%d", client.ID)
	return &RegisterClientReply{
		ClientId: client.ID,
		ClientConfig: &ClientConfig{
			HbDurationSeconds:    int64(config.GetHBDuration().Seconds()),
			TrustDurationSeconds: int64(config.GetTrustDuration().Seconds()),
			Nonce:                0,
			DigestAlgorithm:      config.GetDigestAlgorithm(),
		},
	}, nil
}

// UnregisterClient unregisters a client from cache and database, reserved its database record and files.
func (s *rasService) UnregisterClient(ctx context.Context, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	cid := in.GetClientId()
	//logger.L.Sugar().Debugf("get UnregisterClient %d request", cid)
	trustmgr.UnRegisterClientByID(cid)
	//logger.L.Sugar().Debugf("send UnregisterClient reply")
	return &UnregisterClientReply{Result: true}, nil
}

// SendHeartbeat sends heart beat message to ras and get next action back.
func (s *rasService) SendHeartbeat(ctx context.Context, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	var out SendHeartbeatReply
	cid := in.GetClientId()
	//logger.L.Sugar().Debugf("get hb from %d", cid)
	cmds, nonce := trustmgr.HandleHeartbeat(cid)
	if cmds == typdefs.CmdNone {
		out = SendHeartbeatReply{
			NextAction: cmds,
		}
		//logger.L.Sugar().Debugf("send reply to %d, NextActions=%d", cid, cmds)
	} else {
		out = SendHeartbeatReply{
			NextAction: cmds,
			ClientConfig: &ClientConfig{
				HbDurationSeconds:    int64(config.GetHBDuration().Seconds()),
				TrustDurationSeconds: int64(config.GetTrustDuration().Seconds()),
				Nonce:                nonce,
				DigestAlgorithm:      config.GetDigestAlgorithm(),
			},
		}
		//logger.L.Sugar().Debugf("send reply to %d, NextActions=%d ClientConfig=%+v", cid, cmds, out.ClientConfig)
	}
	return &out, nil
}

// SendReport saves the trust report from client into database/files and verifies it.
func (s *rasService) SendReport(ctx context.Context, in *SendReportRequest) (*SendReportReply, error) {
	cid := in.GetClientId()
	//logger.L.Sugar().Debugf("get SendReport %d request", cid)
	var ms []typdefs.Manifest
	ms = make([]typdefs.Manifest, 0, 3)
	inms := in.GetManifests()
	for _, im := range inms {
		m := typdefs.Manifest{
			Key:   im.Key,
			Value: im.Value,
		}
		ms = append(ms, m)
	}
	trustReport := typdefs.TrustReport{
		ClientID:   in.ClientId,
		Nonce:      in.GetNonce(),
		ClientInfo: in.GetClientInfo(),
		Quoted:     in.GetQuoted(),
		Signature:  in.GetSignature(),
		Manifests:  ms,
		TaReports:  in.GetTaReports(),
	}
	//logger.L.Debug("validate report and save...")
	_, err := trustmgr.ValidateReport(&trustReport)
	if err != nil {
		logger.L.Sugar().Errorf("validate client(%d) report error, %v", cid, err)
		return &SendReportReply{Result: false}, nil
	}

	err = trustmgr.HandleBaseValue(&trustReport)
	if err != nil {
		logger.L.Sugar().Errorf("handle client(%d) basevalue error, %v", cid, err)
		return &SendReportReply{Result: false}, nil
	}
	//logger.L.Sugar().Debugf("validate success and send reply to %d", cid)
	return &SendReportReply{Result: true}, nil
}

func (s *rasService) SendKCMPubKeyCert(ctx context.Context, in *SendKCMPubKeyCertRequest) (*SendKCMPubKeyCertReply, error) {

	kcmPubKeyCert, err := kcmstools.SendKCMPubKeyCert()
	if err != nil {
		logger.L.Sugar().Errorf("Send KCM public key cert error, %v", err)
		return &SendKCMPubKeyCertReply{Result: false}, err
	} else {
		out := SendKCMPubKeyCertReply{
			Result:        true,
			KcmPubKeyCert: kcmPubKeyCert,
		}
		return &out, nil
	}
}

func (s *rasService) VerifyKTAPubKeyCert(ctx context.Context, in *VerifyKTAPubKeyCertRequest) (*VerifyKTAPubKeyCertReply, error) {
	deviceId := in.GetClientId()
	if deviceId == 0 {
		//logger.L.Sugar().Errorf("Outside json is empty")
		return &VerifyKTAPubKeyCertReply{Result: false}, nil
	}

	ktaPem := in.GetKtaPubKeyCert()

	dbConfig := GetdbConfig(strDbConfig)
	kdb.CreateKdbManager(constDB, dbConfig)
	defer kdb.ReleaseKdbManager()

	logger.L.Sugar().Debugf("Going to verify cert of KTA %x", deviceId)
	err := kcmstools.VerifyKTAPubKeyCert(deviceId, ktaPem)
	if err != nil {
		logger.L.Sugar().Errorf("Verify cert of KTA %x error result, %v", deviceId, err)
		return &VerifyKTAPubKeyCertReply{Result: false}, err
	} else {
		logger.L.Sugar().Debugf("Have already verified cert of KTA %x", deviceId)
	}
	//defer kdb.DeletePubKeyInfo(deviceId)
	return &VerifyKTAPubKeyCertReply{Result: true}, nil
}

func (s *rasService) KeyOperation(ctx context.Context, in *KeyOperationRequest) (*KeyOperationReply, error) {
	deviceId := in.GetClientId()
	encCmdData := in.GetEncMessage()
	if len(encCmdData) == 0 {
		//logger.L.Sugar().Errorf("Outside json is empty")
		return &KeyOperationReply{Result: false}, nil
	}

	var message *inKeyInfo
	var sessionKey []byte
	var pubkeycert []byte
	var retMessage retKeyInfo

	// TODO: get kcm private key(kcm private key is a global variable now)
	privKey, err := kcmstools.ReadCert(certPath + kcmKeyName)
	if privKey == nil {
		logger.L.Sugar().Errorf("private key is nil, %v", err)
		return &KeyOperationReply{Result: false}, err
	}
	message, err = DecryptKeyOpIncome(encCmdData, privKey)

	switch message.Command {
	case 0x70000001:
		logger.L.Sugar().Debugf("going to call GenerateNewKey()")
		go kmsServer.ExampleServer()
		defer kmsServer.StopServer()
		dbConfig := GetdbConfig(strDbConfig)
		kdb.CreateKdbManager(constDB, dbConfig)
		defer kdb.ReleaseKdbManager()

		retTAId, key, KtaPublickeyCert, plainText, retKeyId, err := kcmstools.GenerateNewKey(message.TAId, message.Account, message.Password, message.HostKeyId, message.KTAId, deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Generate new key of TA %s error, %v", message.TAId, err)
			return &KeyOperationReply{Result: false}, err
		}
		retMessage = retKeyInfo{
			TAId:      retTAId,
			KeyId:     retKeyId,
			PlainText: plainText,
			HostKeyId: message.HostKeyId,
		}

		pubkeycert = KtaPublickeyCert
		sessionKey = key

	case 0x70000002:
		logger.L.Sugar().Debugf("going to call GetKey()")
		go kmsServer.ExampleServer()
		defer kmsServer.StopServer()
		dbConfig := GetdbConfig(strDbConfig)
		kdb.CreateKdbManager(constDB, dbConfig)
		defer kdb.ReleaseKdbManager()

		retTAId, key, KtaPublickeyCert, plainText, retKeyId, err := kcmstools.GetKey(message.TAId, message.Account, message.Password, message.KeyId, message.HostKeyId, message.KTAId, deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Get key of TA %s error, %v", message.TAId, err)
			return &KeyOperationReply{Result: false}, err
		}
		retMessage = retKeyInfo{
			TAId:      retTAId,
			KeyId:     retKeyId,
			PlainText: plainText,
			HostKeyId: message.HostKeyId,
		}

		pubkeycert = KtaPublickeyCert
		sessionKey = key

	case 0x70000003:
		logger.L.Sugar().Debugf("going to call GetKey()")
		go kmsServer.ExampleServer()
		defer kmsServer.StopServer()
		dbConfig := GetdbConfig(strDbConfig)
		kdb.CreateKdbManager(constDB, dbConfig)
		defer kdb.ReleaseKdbManager()

		key, KtaPublickeyCert, err := kcmstools.DeleteKey(message.TAId, message.KeyId, message.KTAId, deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Delete key of TA %s error, %v", message.TAId, err)
			return &KeyOperationReply{Result: false}, err
		}
		retMessage = retKeyInfo{
			TAId:      message.TAId,
			KeyId:     message.KeyId,
			HostKeyId: message.HostKeyId,
		}

		pubkeycert = KtaPublickeyCert
		sessionKey = key

	default:
		logger.L.Sugar().Errorf("resolve command of TA %s failed", message.TAId)
		return &KeyOperationReply{Result: false}, err
	}

	encRetMessage, err := EncryptKeyOpOutcome(retMessage, sessionKey, pubkeycert)
	if err != nil {
		logger.L.Sugar().Errorf("Encode return message of TA %s error, %v", retMessage.TAId, err)
		return &KeyOperationReply{Result: false}, err
	}

	out := KeyOperationReply{
		Result:        true,
		EncRetMessage: encRetMessage,
	}
	return &out, nil
}

type RasConn struct {
	ctx    context.Context
	cancel context.CancelFunc
	conn   *grpc.ClientConn
	c      RasClient
}

// CreateConn creates a grpc connection to remote server at addr:ip.
func CreateConn(addr string) (*RasConn, error) {
	ras := &RasConn{}
	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.L.Sugar().Errorf("connect %s error, %v", addr, err)
		return nil, typdefs.ErrConnectFailed
	}
	ras.conn = conn
	ras.c = NewRasClient(conn)
	ras.ctx, ras.cancel = context.WithTimeout(context.Background(), constTimeOut)
	//logger.L.Sugar().Debugf("connect %s ok", addr)
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
func DoGenerateEKCertWithConn(ras *RasConn, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	//logger.L.Debug("invoke GenerateEKCert...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.GenerateEKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateEKCert error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke GenerateEKCert ok")
	return bk, nil
}

// DoGenerateIKCertWithConn uses existing ras connection to generate an identity certificate from ras server for client.
func DoGenerateIKCertWithConn(ras *RasConn, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	//logger.L.Debug("invoke GenerateIKCert...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.GenerateIKCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke GenerateIKCert error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke GenerateIKCert ok")
	return bk, nil
}

// DoRegisterClientWithConn uses existing ras connection to register the rac to the ras server.
func DoRegisterClientWithConn(ras *RasConn, in *RegisterClientRequest) (*RegisterClientReply, error) {
	//logger.L.Debug("invoke RegisterClient...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.RegisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke RegisterClient error, %v", err)
		return nil, err
	}
	//logger.L.Sugar().Debugf("invoke RegisterClient ok, ClientID=%d", bk.GetClientId())
	return bk, nil
}

// DoUnregisterClientWithConn uses existing ras connection to unregister the rac from the ras server.
func DoUnregisterClientWithConn(ras *RasConn, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	//logger.L.Debug("invoke UnregisterClient...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.UnregisterClient(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke UnregisterClient error, %v", err)
		return nil, err
	}
	//logger.L.Sugar().Debugf("invoke UnregisterClient %v", bk.Result)
	return bk, nil
}

// DoSendHeartbeatWithConn uses existing ras connection to send a heart beat message to the ras server.
func DoSendHeartbeatWithConn(ras *RasConn, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	//logger.L.Debug("invoke SendHeartbeat...")
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
func DoSendReportWithConn(ras *RasConn, in *SendReportRequest) (*SendReportReply, error) {
	//logger.L.Debug("invoke SendReport...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.SendReport(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendReport error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke SendReport ok")
	return bk, nil
}

func DoSendKCMPubKeyCertWithConn(ras *RasConn, in *SendKCMPubKeyCertRequest) (*SendKCMPubKeyCertReply, error) {
	//logger.L.Debug("invoke SendKCMPubKeyCert...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.SendKCMPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke SendKCMPubKeyCert error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke SendKCMPubKeyCert ok")
	return bk, nil
}

func DoVerifyKTAPubKeyCertWithConn(ras *RasConn, in *VerifyKTAPubKeyCertRequest) (*VerifyKTAPubKeyCertReply, error) {
	//logger.L.Debug("invoke VerifyKTAPubKeyCert...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.VerifyKTAPubKeyCert(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke VerifyKTAPubKeyCert error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke VerifyKTAPubKeyCert ok")
	return bk, nil
}

func DoKeyOperationWithConn(ras *RasConn, in *KeyOperationRequest) (*KeyOperationReply, error) {
	//logger.L.Debug("invoke KeyOperation...")
	if ras == nil {
		return nil, ErrClientApiParameterWrong
	}
	bk, err := ras.c.KeyOperation(ras.ctx, in)
	if err != nil {
		logger.L.Sugar().Errorf("invoke KeyOperation error, %v", err)
		return nil, err
	}
	//logger.L.Debug("invoke KeyOperation ok")
	return bk, nil
}

// DoGenerateEKCert generates an ek certificate from ras server for client.
func DoGenerateEKCert(addr string, in *GenerateEKCertRequest) (*GenerateEKCertReply, error) {
	//logger.L.Debug("invoke GenerateEKCert...")
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
	//logger.L.Debug("invoke GenerateEKCert ok")
	return bk, nil
}

// DoGenerateIKCert generates an identity certificate from ras server for client.
func DoGenerateIKCert(addr string, in *GenerateIKCertRequest) (*GenerateIKCertReply, error) {
	//logger.L.Debug("invoke GenerateIKCert...")
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
	//logger.L.Debug("invoke GenerateIKCert ok")
	return bk, nil
}

// DoRegisterClient registers the rac to the ras server.
func DoRegisterClient(addr string, in *RegisterClientRequest) (*RegisterClientReply, error) {
	//logger.L.Debug("invoke RegisterClient...")
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
	//logger.L.Sugar().Debugf("invoke RegisterClient ok, ClientID=%d", bk.GetClientId())
	return bk, nil
}

// DoUnregisterClient unregisters the rac from the ras server.
func DoUnregisterClient(addr string, in *UnregisterClientRequest) (*UnregisterClientReply, error) {
	//logger.L.Debug("invoke UnregisterClient...")
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
	//logger.L.Sugar().Debugf("invoke UnregisterClient %v", bk.Result)
	return bk, nil
}

// DoSendHeartbeat sends a heart beat message to the ras server.
func DoSendHeartbeat(addr string, in *SendHeartbeatRequest) (*SendHeartbeatReply, error) {
	//logger.L.Debug("invoke SendHeartbeat...")
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
	/*
		if bk.GetClientConfig() != nil {
			logger.L.Sugar().Debugf("invoke SendHeartbeat ok, NextActions=%d ClientConfig=%+v",
				bk.GetNextAction(), bk.GetClientConfig())
		} else {
			logger.L.Sugar().Debugf("invoke SendHeartbeat ok, NextActions=%d",
				bk.GetNextAction())
		}
	*/
	return bk, nil
}

// DoSendReport sends a trust report message to the ras server.
func DoSendReport(addr string, in *SendReportRequest) (*SendReportReply, error) {
	//logger.L.Debug("invoke SendReport...")
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
	//logger.L.Debug("invoke SendReport ok")
	return bk, nil
}

func DoSendKCMPubKeyCert(addr string, in *SendKCMPubKeyCertRequest) (*SendKCMPubKeyCertReply, error) {
	//logger.L.Debug("invoke SendKCMPubKeyCert...")
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
	//logger.L.Sugar().Debugf("invoke SendKCMPubKeyCert %v", bk.Result)
	return bk, nil
}

func DoVerifyKTAPubKeyCert(addr string, in *VerifyKTAPubKeyCertRequest) (*VerifyKTAPubKeyCertReply, error) {
	//logger.L.Debug("invoke VerifyKTAPubKeyCert...")
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
	//logger.L.Sugar().Debugf("invoke VerifyKTAPubKeyCert %v", bk.Result)
	return bk, nil
}

func DoKeyOperation(addr string, in *KeyOperationRequest) (*KeyOperationReply, error) {
	//logger.L.Debug("invoke KeyOperation...")
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
	//logger.L.Sugar().Debugf("invoke KeyOperation %v", bk.Result)
	return bk, nil
}

func GetdbConfig(strDbConfig string) string {
	return fmt.Sprintf(strDbConfig, config.GetDBUser(), config.GetDBPassword(),
		config.GetDBName(), config.GetDBHost(), config.GetDBPort())
}

func aesGCMEncrypt(key, plainText []byte) ([]byte, []byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.L.Sugar().Errorf("create NewCipher error, %v", err)
		return nil, nil, nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.L.Sugar().Errorf("create NewGCM error, %v", err)
		return nil, nil, nil, err
	}
	Nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, Nonce); err != nil {
		logger.L.Sugar().Errorf("create nonce error, %v", err)
		return nil, nil, nil, err
	}
	cipher := aesGCM.Seal(nil, Nonce, plainText, nil)
	tlength := aesGCM.Overhead() // length of tag
	return cipher[:len(cipher)-tlength], cipher[len(cipher)-tlength:], Nonce, nil
}

func aesGCMDecrypt(key, cipherText, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.L.Sugar().Errorf("create NewCipher error, %v", err)
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.L.Sugar().Errorf("create NewGCM error, %v", err)
		return nil, err
	}
	plain, err := aesGCM.Open(nil, nonce, cipherText, nil) // error, message authentication failed
	if err != nil {
		logger.L.Sugar().Errorf("aesgcm decode error, %v", err)
		return nil, err
	}
	return plain, nil
}

func RsaEncrypt(data, keyBytes []byte) ([]byte, error) {
	//解密pem格式的公钥
	block, _ := pem.Decode(keyBytes)
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.L.Sugar().Errorf("rsa pem decode error, %v", err)
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		logger.L.Sugar().Errorf("rsa encode error, %v", err)
		return nil, err
	}
	return ciphertext, nil
}

func RsaDecrypt(ciphertext, keyBytes []byte) ([]byte, error) {
	//获取私钥
	block, _ := pem.Decode(keyBytes)
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.L.Sugar().Errorf("x509 decode fail, %v", err)
		return nil, err
	}
	if priv == nil {
		logger.L.Sugar().Errorf("x509 key is nil, %v", err)
		return nil, err
	}
	// 解密
	data, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		logger.L.Sugar().Errorf("rsa decode error, %v", err)
		return nil, err
	}
	if data == nil {
		logger.L.Sugar().Errorf("data is nil")
		return nil, err
	}
	return data, nil
}

func EncryptKeyOpOutcome(retMessage retKeyInfo, sessionKey, KtaPublickeyCert []byte) ([]byte, error) {
	str_taId := string(retMessage.TAId)
	jsonRetMessage, err := json.Marshal(retMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode inside json message of TA %s error, %v", str_taId, err)
		return nil, err
	}

	pubkeycert, _, err := cryptotools.DecodeKeyCertFromPEM(KtaPublickeyCert)
	if err != nil {
		return nil, err
	}

	//TODO: use sessionKey to encrypt jsonRetMessage
	encRetMessage, tag, nonce, err := aesGCMEncrypt(sessionKey, jsonRetMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode return message(json format) of TA %s after get key, error, %v", str_taId, err)
		return nil, err
	}
	appendKey := append(nonce, sessionKey...)
	appendKey = append(appendKey, tag...)

	label := []byte("label")
	encSessionKey, err := cryptotools.AsymmetricEncrypt(cryptotools.AlgRSA, cryptotools.AlgNull, pubkeycert.PublicKey, appendKey, label)
	if err != nil {
		return nil, err
	}

	encKey := hex.EncodeToString(encSessionKey)
	encMessage := hex.EncodeToString(encRetMessage)

	//TODO: pack encrypted encRetMessage and encSessionKey as struct
	finalMessage := tagCmdData{
		Key:        []byte(encKey),
		EncCmdData: []byte(encMessage),
	}

	//TODO encrypt the struct to json format
	finalRetMessage, err := json.Marshal(finalMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode outside json message of TA %s error, %v", str_taId, err)
		return nil, err
	}

	return finalRetMessage, nil
}

func DecryptKeyOpIncome(encCmdData, privKey []byte) (*inKeyInfo, error) {
	var cmdData tagCmdData
	var message inKeyInfo
	err := json.Unmarshal(encCmdData, &cmdData)
	if err != nil {
		logger.L.Sugar().Errorf("Decode outside json of TA error, %v", err)
		return &message, err
	}

	sessionKey, err := hex.DecodeString(string(cmdData.Key))
	if err != nil {
		logger.L.Sugar().Errorf("decode session key from hex error, %v", err)
		return nil, err
	}
	decCmdData, err := hex.DecodeString(string(cmdData.EncCmdData))
	if err != nil {
		logger.L.Sugar().Errorf("decode cmd data from hex error, %v", err)
		return nil, err
	}

	// TODO: use kcm private key to decode key
	// decKey := RsaDecrypt(cmdData.Key, privKey)
	block, _ := pem.Decode(privKey)
	// 解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		logger.L.Sugar().Errorf("decode private key from x509 error, %v", err)
		return nil, err
	}
	if priv == nil {
		logger.L.Sugar().Errorf("private key is nil, %v", err)
		return nil, err
	}

	label := []byte("label")
	decSessionKey, err := cryptotools.AsymmetricDecrypt(cryptotools.AlgRSA, cryptotools.AlgNull, priv, sessionKey, label)
	if err != nil {
		return nil, err
	}

	nonce := decSessionKey[:12]
	decKey := decSessionKey[12 : len(decSessionKey)-16]
	tag := decSessionKey[len(decSessionKey)-16:]

	appendCmdData := append(decCmdData, tag...)

	// TODO: use decoded key to decode cmdData.encCmdData and save the result in encMessage
	encMessage, err := aesGCMDecrypt(decKey, appendCmdData, nonce) // Encrypt algorithm: AES GCM (256bit) (AES256GCM)
	if err != nil {
		logger.L.Sugar().Errorf("Decode AESGCM error, %v", err)
		return nil, err
	}

	err = json.Unmarshal(encMessage, &message)
	if err != nil {
		logger.L.Sugar().Errorf("Decode inside json of TA error, %v", err)
		return nil, err
	}

	return &message, nil
}
