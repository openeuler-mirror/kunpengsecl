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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	kcmPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAwSJfAG/41gODhRpcVDVoe6Vjxc++u+T68fphzp9Jn58Am+O1
DdB0GpnAdFQd2kyhvutAK5NlvC6EcTy0zqGXLfgOmDcQRtOn9/W3Lb+PTK8TgI5g
l3tBUovJ5696/9MPal/4kUX49hETeMinVjvgK3sKbuel3kn+FlHd3ElrG3p3/jb0
SCknJXe3HQ4O9dBNXAiT4qMUQoS58Gs/0feKgILuNcThHHFjGNVuirkxevVopzsu
0EcU4fN3oh4fiVEn8WvWghjiOZsJ4GXi1YpcRtkOwRRkQXZhYqdq1dFOHKizHyep
3/ShY3VeCw2k29Hc6OpXkBdjhY/sXAMexfN2XwIDAQABAoIBAQCweyXwkmEBvyg5
QoNH953IDrODGHij3XNqFm+1jVyLXZIC4Sqauva9L+3q3sqApjHO8c0rhH8cXC1u
BBj8EDDDMr6zXO2kqtf7/y4pwbfCTOE3QeMFyP1B3rba3UE577VQcO4EYbpDsAro
/gHbDM+lK8O24DpzS43A+4IOP5B+A+1QDB8nXnOKA38l/W2HvTHbym2FY9WHYqlr
vbdWFupSEZNVS+slK+H5plU+un9Mdf1HToj9Jv8ptqwDJQsD/6fls24bmq5+TF0X
KklC6MdXJ8gQ2d5YMWNkXCZARFUj3YBOOvi5XMUx9GnQw45LWaRKRJWuUXMRmRkw
ACZHMwqhAoGBAPFfHe7KHIUkJ8vT6vYpyIhjalCqWE1Ce0Kl+cnlrWgYIxNzXoy1
4cg5BHpMKqw4ScOOwxfrF6Dm/NpWHuQTWB+ekzSS85LlMudASFuLJDYhaqB0dx3C
pYJY7y+CVmKKHW14UHoFjy3z1wM3dG+8ASjlRBZhHOGjM1PpZadu5/EnAoGBAMzW
2hmYOKaV8TF/PIIdP4xv6MQ72fqVRN+gzDFUoKeFOs2fnVyG0GoXpvaZeVoHmJA4
dDCHOb7R/pV1KtE8hnonyx3SWO6LV7sx1kZEFtnBirdYGvL1CmUCy+SmEQt2Jey2
LE1st0bLqj1cE/vFFC/Ar3Z16wkF3gzCkKYvmaQJAoGBAKaz6cl1P5NY8D9fQoT3
QK+p8dB6hff+NYFHfqhJf6VIHlmdsax/JcwSTRxmJIbDbXapz+ZiEPSo8/ObzUP6
dD+KVuLVp3JJ6Ak9JXxMMhtMowbkySv9ti+7Wp62ZxExkLd9hB9yXXwAT/zBvSI6
d5aWGZtXQQo5nAaVSQcFmx27AoGBAMw+BmWy0/m2VDIoTermwvCCvTK9AtHKeEwK
hs9BNJcUTtesKTmS6sh+IOqNiORt4n8a6y9gBgHwXMolc7YBhYzTlMF9dVMU+Tsb
rC2PwsEJLAk3/lb2YZDqQucPdrtY6OOnmXDxz6T1eh+IahyGG2Sp2cpiNSJgCVHr
xlMN70IRAoGBAK8lkBISg5JL7fQVq0v00CVxF1HbKHb6BU5TlSksbhiWu7tPo6JS
KNP4YufzR0vTsIbUiwqBVgWWwpg/axa5Az+obzZpb0gir/tDOFAKRGCOyDeGnm1Q
YNTm0LULYytmAi45+h9jDemMzMcnMSWUZsOu599U2CitMGTegL9KmCuk
-----END RSA PRIVATE KEY-----`
	constDB = "postgres"
)

type rasService struct {
	UnimplementedRasServer
}

type tagCmdData struct {
	key        []byte
	encCmdData []byte
}

type inKeyInfo struct {
	taId      []byte
	account   []byte
	password  []byte
	keyId     []byte
	hostKeyId []byte
	command   uint32
}

type retKeyInfo struct {
	taId      []byte
	keyId     []byte
	plainText []byte
	hostKeyId []byte
	encKey    []byte
}

var (
	ErrClientApiParameterWrong = errors.New("client api parameter wrong")

	srv *grpc.Server = nil
)

// var dbConfig string = "user=postgres password=postgres dbname=kunpengsecl host=localhost port=5432 sslmode=disable"

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
	dbConfig := GetdbConfig(strDbConfig)
	trustmgr.CreateTrustManager(constDB, dbConfig)
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
		return &SendKCMPubKeyCertReply{Result: false}, nil
	} else {
		out := SendKCMPubKeyCertReply{
			Result:        true,
			KcmPubKeyCert: kcmPubKeyCert,
		}
		return &out, nil
	}
}

func (s *rasService) VerifyKTAPubKeyCert(ctx context.Context, in *VerifyKTAPubKeyCertRequest) (*VerifyKTAPubKeyCertReply, error) {
	dbConfig := GetdbConfig(strDbConfig)
	// fmt.Printf("----------------------------------\ndbConfig: %s\n", dbConfig)
	kdb.CreateKdbManager(constDB, dbConfig)

	ktaDer := in.GetKtaPubKeyCert()
	ktaPem, err := cryptotools.EncodeKeyCertToPEM(ktaDer)
	if err != nil {
		logger.L.Sugar().Errorf("encode KTA public key cert to PEM fail, %v", err)
		return &VerifyKTAPubKeyCertReply{Result: false}, err
	}

	deviceId := in.GetClientId()

	err = kcmstools.VerifyKTAPubKeyCert(deviceId, string(ktaPem))
	if err != nil {
		logger.L.Sugar().Errorf("Verify cert of KTA %x error, %v", deviceId, err)
		return &VerifyKTAPubKeyCertReply{Result: false}, nil
	}
	return &VerifyKTAPubKeyCertReply{Result: true}, nil
}

func (s *rasService) KeyOperation(ctx context.Context, in *KeyOperationRequest) (*KeyOperationReply, error) {

	encCmdData := in.GetEncMessage()
	var cmdData tagCmdData
	var encMessage []byte
	var message inKeyInfo
	var retMessage retKeyInfo
	var encRetMessage []byte
	err := json.Unmarshal(encCmdData, &cmdData)
	if err != nil {
		logger.L.Sugar().Errorf("Decode outside json of TA error, %v", err)
		return &KeyOperationReply{Result: false}, nil
	}
	dbConfig := GetdbConfig(strDbConfig)
	kdb.CreateKdbManager(constDB, dbConfig)

	// TODO: get kcm private key
	kcmPrivKey, _, err := cryptotools.DecodePrivateKeyFromPEM([]byte(kcmPrivateKey))
	if err != nil {
		logger.L.Sugar().Errorf("Decode kcm private key error, %v", err)
		return &KeyOperationReply{Result: false}, nil
	}

	// TODO: decode cmdData.key by kcm private key
	label := []byte("label")
	decKey, err := cryptotools.AsymmetricDecrypt(0x0001, 0x0000, kcmPrivKey, cmdData.key, label)

	// TODO: use decoded key to decode cmdData.encCmdData and save the result in encMessage
	encMessage, err = aesGCMDecrypt(decKey, cmdData.encCmdData) // Encrypt algorithm: AES GCM (256bit) (AES256GCM)
	if err != nil {
		logger.L.Sugar().Errorf("Decode AESGCM error, %v", err)
		return &KeyOperationReply{Result: false}, nil
	}

	err = json.Unmarshal(encMessage, &message)
	if err != nil {
		logger.L.Sugar().Errorf("Decode inside json of TA error, %v", err)
		return &KeyOperationReply{Result: false}, nil
	}

	switch message.command {
	case 0x80000001:
		retTAId, encKey, plainText, retKeyId, err := kcmstools.GenerateNewKey(message.taId, message.account, message.password, message.hostKeyId)
		if err != nil {
			logger.L.Sugar().Errorf("Generate new key of TA %s error, %v", message.taId, err)
			return &KeyOperationReply{Result: false}, nil
		}
		retMessage = retKeyInfo{
			taId:      retTAId,
			keyId:     retKeyId,
			plainText: plainText,
			hostKeyId: message.hostKeyId,
			encKey:    encKey,
		}
	case 0x80000002:
		retTAId, encKey, plainText, retKeyId, err := kcmstools.GetKey(message.taId, message.account, message.password, message.keyId, message.hostKeyId)
		if err != nil {
			logger.L.Sugar().Errorf("Get key of TA %s error, %v", message.taId, err)
			return &KeyOperationReply{Result: false}, nil
		}
		retMessage = retKeyInfo{
			taId:      retTAId,
			keyId:     retKeyId,
			plainText: plainText,
			hostKeyId: message.hostKeyId,
			encKey:    encKey,
		}
	case 0x80000003:
		err := kcmstools.DeleteKey(message.taId, message.keyId)
		if err != nil {
			logger.L.Sugar().Errorf("Delete key of TA %s error, %v", message.taId, err)
			return &KeyOperationReply{Result: false}, nil
		}
		retMessage = retKeyInfo{
			taId:      message.taId,
			keyId:     message.keyId,
			hostKeyId: message.hostKeyId,
		}
	case 0x80000004:
		fallthrough
	default:
		logger.L.Sugar().Errorf("resolve command of TA %s failed", message.taId)
		return &KeyOperationReply{Result: false}, nil
	}

	encRetMessage, err = json.Marshal(retMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode return message of TA %s after get key, error, %v", message.taId, err)
		return &KeyOperationReply{Result: false}, nil
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

func aesGCMDecrypt(key, cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	plain, err := aesGCM.Open(nonce, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func GetdbConfig(strDbConfig string) string {
	return fmt.Sprintf(strDbConfig, config.GetDBUser(), config.GetDBPassword(),
		config.GetDBName(), config.GetDBHost(), config.GetDBPort())
}
