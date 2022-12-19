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
	"errors"
	"encoding/json"
	"encoding/pem"
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
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kcmstools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
	kmsServer "gitee.com/openeuler/kunpengsecl/attestation/kms"
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

const (
	kcmCert = `
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=CN, ST=Shanghai, L=Shanghai, O=Huawei, CN=ca
        Validity
            Not Before: Dec  9 00:36:05 2022 GMT
            Not After : Nov 30 00:36:05 2023 GMT
        Subject: C=CN, ST=Shanghai, L=Shanghai, O=Huawei, CN=kcm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:cf:e5:72:98:85:46:34:54:51:fe:bd:f4:3f:7a:
                    24:57:44:36:76:02:75:0a:ff:bf:e2:c4:8f:6f:50:
                    54:d2:6d:3a:13:fa:17:f7:1b:df:9b:6f:2a:22:3f:
                    b2:a4:ad:b7:bc:64:36:fb:69:ec:15:52:b1:ba:b7:
                    6c:2c:5b:89:2b:50:3b:1d:be:a7:4f:91:19:d2:6e:
                    49:47:6b:45:f2:7d:9c:94:fa:f5:d8:86:e6:37:04:
                    8e:aa:06:1e:3e:e2:95:27:9b:f7:f5:e6:34:d7:2f:
                    1e:46:bd:90:89:be:43:0d:cf:c4:91:19:80:26:95:
                    3c:1f:f1:bd:23:01:c3:50:92:69:1a:07:c2:e6:af:
                    07:47:fe:a2:41:04:1c:9a:ca:ed:5d:fc:b4:93:72:
                    c0:ee:58:5b:2a:e8:81:e6:7c:ae:d1:4e:d0:59:14:
                    ea:f6:4f:bc:01:e4:39:af:1b:db:05:01:c3:b2:da:
                    25:f4:86:10:d9:92:81:aa:e5:d6:fd:09:a8:3c:e3:
                    d0:37:df:a9:de:5b:65:7c:f6:90:7c:ff:1b:83:67:
                    47:a5:3f:95:1f:3e:43:70:20:d5:29:0b:30:24:fb:
                    a8:c1:6c:44:99:69:c1:4a:bf:65:b6:83:bf:f3:5c:
                    33:43:11:db:63:ea:01:85:4e:6a:e5:26:20:75:5e:
                    79:23
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            Netscape Comment: 
                OpenSSL Generated Certificate
            X509v3 Subject Key Identifier: 
                AC:68:E3:D5:5A:64:E6:1B:DB:32:1F:BA:01:5C:6A:ED:08:13:F5:E2
            X509v3 Authority Key Identifier: 
                keyid:F7:CC:87:ED:0D:1F:86:8B:C5:34:8E:47:08:47:AA:70:AF:EF:82:A6

    Signature Algorithm: sha256WithRSAEncryption
         a7:af:17:de:eb:7b:32:82:0b:f6:58:c1:15:5a:0a:01:57:81:
         fb:4f:b2:e4:d8:27:27:bb:3e:cf:cd:6f:17:a1:75:25:5e:ec:
         5a:57:8c:79:f3:69:39:54:35:1b:7f:a2:30:74:1d:3d:33:79:
         ce:72:e8:7e:51:f3:e7:fd:80:ab:a1:ec:b4:7c:26:16:a8:09:
         e9:91:d4:b2:7a:ba:a6:ee:73:d8:64:27:13:d9:55:51:33:3c:
         f6:2f:2f:be:27:c6:7a:15:e3:49:f8:5f:c9:50:af:5a:fc:9b:
         fb:fc:f9:09:0e:ba:b7:f3:5a:f3:13:05:2d:56:b9:46:ce:ec:
         ae:b5:66:7b:e3:16:72:27:01:e1:d5:d3:c5:43:66:5f:b1:9c:
         4d:bc:69:df:8a:b2:cc:a9:6d:bc:2d:36:76:ee:ae:20:9a:3d:
         75:a1:ea:f0:58:e6:29:81:68:aa:09:56:23:80:a8:cf:92:9f:
         01:e0:2c:f0:21:c0:63:2d:21:50:e7:d6:c0:8a:1c:f7:50:ba:
         e1:05:f4:96:a7:b7:54:7c:e2:80:0c:de:c6:c7:bd:86:8a:84:
         4b:11:09:79:0e:b4:5c:9d:b2:44:9a:ed:0c:ee:22:3f:f9:e3:
         24:75:2e:44:60:c7:7b:c5:8e:fd:36:8d:60:95:70:54:f2:82:
         4a:5f:f8:50
-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJDTjER
MA8GA1UECAwIU2hhbmdoYWkxETAPBgNVBAcMCFNoYW5naGFpMQ8wDQYDVQQKDAZI
dWF3ZWkxCzAJBgNVBAMMAmNhMB4XDTIyMTIwOTAwMzYwNVoXDTIzMTEzMDAwMzYw
NVowUjELMAkGA1UEBhMCQ04xETAPBgNVBAgMCFNoYW5naGFpMREwDwYDVQQHDAhT
aGFuZ2hhaTEPMA0GA1UECgwGSHVhd2VpMQwwCgYDVQQDDANrY20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP5XKYhUY0VFH+vfQ/eiRXRDZ2AnUK/7/i
xI9vUFTSbToT+hf3G9+bbyoiP7Kkrbe8ZDb7aewVUrG6t2wsW4krUDsdvqdPkRnS
bklHa0XyfZyU+vXYhuY3BI6qBh4+4pUnm/f15jTXLx5GvZCJvkMNz8SRGYAmlTwf
8b0jAcNQkmkaB8LmrwdH/qJBBByayu1d/LSTcsDuWFsq6IHmfK7RTtBZFOr2T7wB
5DmvG9sFAcOy2iX0hhDZkoGq5db9Cag849A336neW2V89pB8/xuDZ0elP5UfPkNw
INUpCzAk+6jBbESZacFKv2W2g7/zXDNDEdtj6gGFTmrlJiB1XnkjAgMBAAGjezB5
MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENl
cnRpZmljYXRlMB0GA1UdDgQWBBSsaOPVWmTmG9syH7oBXGrtCBP14jAfBgNVHSME
GDAWgBT3zIftDR+Gi8U0jkcIR6pwr++CpjANBgkqhkiG9w0BAQsFAAOCAQEAp68X
3ut7MoIL9ljBFVoKAVeB+0+y5NgnJ7s+z81vF6F1JV7sWleMefNpOVQ1G3+iMHQd
PTN5znLoflHz5/2Aq6HstHwmFqgJ6ZHUsnq6pu5z2GQnE9lVUTM89i8vvifGehXj
SfhfyVCvWvyb+/z5CQ66t/Na8xMFLVa5Rs7srrVme+MWcicB4dXTxUNmX7GcTbxp
34qyzKltvC02du6uIJo9daHq8FjmKYFoqglWI4Coz5KfAeAs8CHAYy0hUOfWwIoc
91C64QX0lqe3VHzigAzexse9hoqESxEJeQ60XJ2yRJrtDO4iP/njJHUuRGDHe8WO
/TaNYJVwVPKCSl/4UA==
-----END CERTIFICATE-----`
)

var (
	/*decKey = []byte{
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e}*/
	certPath = "../cert/"
	kcmFileName = "kcm.crt"
	ktaFileName  = "kta.crt"
	rootFileName = "ca.crt"
)

//var Nonce []byte
var privKey []byte
var kcmPublicKey []byte

type rasService struct {
	UnimplementedRasServer
}

type tagCmdData struct {
	Key			[]byte
	EncCmdData	[]byte
}

type inKeyInfo struct {
	TAId		[]byte
	Account		[]byte
	Password	[]byte
	KeyId		[]byte
	HostKeyId	[]byte
	Command		uint32
}

type retKeyInfo struct {
	TAId		[]byte
	KeyId		[]byte
	PlainText	[]byte
	HostKeyId	[]byte
	Cmd			uint32
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
	if err != nil{
		logger.L.Sugar().Errorf("Send KCM public key cert error, %v", err)
		return &SendKCMPubKeyCertReply{Result: false}, err
	} else {
		out := SendKCMPubKeyCertReply{
			Result:		true,
			KcmPubKeyCert:	kcmPubKeyCert,
		}
		return &out, nil
	}
}

func (s *rasService) VerifyKTAPubKeyCert(ctx context.Context, in *VerifyKTAPubKeyCertRequest) (*VerifyKTAPubKeyCertReply, error) {
	deviceId := in.GetClientId()
	if deviceId == 0{
		//logger.L.Sugar().Errorf("Outside json is empty")
		return &VerifyKTAPubKeyCertReply{Result: false}, nil
	}

	dbConfig := GetdbConfig(strDbConfig)
	kdb.CreateKdbManager(constDB, dbConfig)
	defer kdb.ReleaseKdbManager()

	ktaPem := in.GetKtaPubKeyCert()

	logger.L.Sugar().Debugf("Going to verify cert of KTA %x", deviceId)
	err := kcmstools.VerifyKTAPubKeyCert(deviceId, ktaPem)
	if err != nil{
		logger.L.Sugar().Errorf("Verify cert of KTA %x error result, %v", deviceId, err)
		return &VerifyKTAPubKeyCertReply{Result: false}, err
	}else{
		logger.L.Sugar().Debugf("Have already verified cert of KTA %x", deviceId)
	}
	defer kdb.DeletePubKeyInfo(deviceId)
	return &VerifyKTAPubKeyCertReply{Result: true}, nil
}

func (s *rasService) KeyOperation(ctx context.Context, in *KeyOperationRequest) (*KeyOperationReply, error) {

	encCmdData := in.GetEncMessage()
	if len(encCmdData) == 0{
		//logger.L.Sugar().Errorf("Outside json is empty")
		return &KeyOperationReply{Result: false}, nil
	}

	var message inKeyInfo
	var sessionKey []byte
	var encSessionKey []byte
	var retMessage retKeyInfo

	message, err := DecryptKeyOpIncome(encCmdData)

	switch message.Command {
		case 0x80000001:
			logger.L.Sugar().Debugf("going to call GenerateNewKey()")
			go kmsServer.ExampleServer()
			defer kmsServer.StopServer()
			dbConfig := GetdbConfig(strDbConfig)
			kdb.CreateKdbManager(constDB, dbConfig)
			defer kdb.ReleaseKdbManager()

			retTAId, key, encKey, plainText, retKeyId, err := kcmstools.GenerateNewKey(message.TAId, message.Account, message.Password, message.HostKeyId)
			if err != nil{
				logger.L.Sugar().Errorf("Generate new key of TA %s error, %v", message.TAId, err)
				return &KeyOperationReply{Result: false}, err
			}
			retMessage = retKeyInfo {
				TAId:		retTAId,
				KeyId:		retKeyId,
				PlainText:	plainText,
				HostKeyId:	message.HostKeyId,
				Cmd:		message.Command,
			}
			sessionKey = key
			encSessionKey = encKey
		case 0x80000002:
			logger.L.Sugar().Debugf("going to call GetKey()")
			go kmsServer.ExampleServer()
			defer kmsServer.StopServer()
			dbConfig := GetdbConfig(strDbConfig)
			kdb.CreateKdbManager(constDB, dbConfig)
			defer kdb.ReleaseKdbManager()

			retTAId, key, encKey, plainText, retKeyId, err := kcmstools.GetKey(message.TAId, message.Account, message.Password, message.KeyId, message.HostKeyId)
			if err != nil{
				logger.L.Sugar().Errorf("Get key of TA %s error, %v", message.TAId, err)
				return &KeyOperationReply{Result: false}, err
			}
			retMessage = retKeyInfo {
				TAId:		retTAId,
				KeyId:		retKeyId,
				PlainText:	plainText,
				HostKeyId:	message.HostKeyId,
				Cmd:		message.Command,
			}
			sessionKey = key
			encSessionKey = encKey
		case 0x80000003:
			logger.L.Sugar().Debugf("going to call GetKey()")
			go kmsServer.ExampleServer()
			defer kmsServer.StopServer()
			dbConfig := GetdbConfig(strDbConfig)
			kdb.CreateKdbManager(constDB, dbConfig)
			defer kdb.ReleaseKdbManager()

			err = kcmstools.DeleteKey(message.TAId, message.KeyId)
			if err != nil{
				logger.L.Sugar().Errorf("Delete key of TA %s error, %v", message.TAId, err)
				return &KeyOperationReply{Result: false}, err
			}
			retMessage = retKeyInfo {
				TAId:		message.TAId,
				KeyId:		message.KeyId,
				HostKeyId:	message.HostKeyId,
				Cmd:		message.Command,
			}
			sessionKey = make([]byte, 32)
			ktaPublicKey := kcmPublicKey	// use kcms' public key as a temporary pulic key
			encSessionKey = RsaEncrypt(sessionKey, ktaPublicKey)
		default:
			logger.L.Sugar().Errorf("resolve command of TA %s failed", message.TAId)
			return &KeyOperationReply{Result: false}, err
	}

	encRetMessage, err := EncryptKeyOpOutcome(retMessage, sessionKey, encSessionKey)
	if err != nil{
		logger.L.Sugar().Errorf("Encode return message of TA %s error, %v", retMessage.TAId, err)
		return &KeyOperationReply{Result: false}, err
	}

	out := KeyOperationReply{
		Result:		true,
		EncRetMessage:	encRetMessage,
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

func aesGCMEncrypt(key, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	Nonce := make([]byte, aesGCM.NonceSize())
	cipher := aesGCM.Seal(nil, Nonce, plainText, nil)
	return cipher, nil
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
	Nonce := make([]byte, aesGCM.NonceSize())
	plain, err := aesGCM.Open(nil, Nonce, cipherText, nil)	// error, message authentication failed
	if err != nil {
		logger.L.Sugar().Errorf("aesgcm decode error, %v", err)
		return nil, err
	}
	return plain, nil
}

func RsaEncrypt(data, keyBytes []byte) []byte {
	//解密pem格式的公钥
	block, _ := pem.Decode(keyBytes)
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		panic(err)
	}
	return ciphertext
}

func RsaDecrypt(ciphertext, keyBytes []byte) []byte {
	//获取私钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key is nil"))
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(errors.New("x509 decode fail"))
	}
	if priv == nil {
		panic(errors.New("x509 key is nil"))
	}
	// 解密
	data, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		logger.L.Sugar().Errorf("rsa decode error, %v", err)
	}
	if data == nil {
		logger.L.Sugar().Errorf("data is nil")
	}
	return data
}

func EncryptKeyOpOutcome(retMessage retKeyInfo, sessionKey, encSessionKey[]byte)([]byte, error){
	str_taId := string(retMessage.TAId)
	jsonRetMessage, err := json.Marshal(retMessage)
	if err != nil{
		logger.L.Sugar().Errorf("Encode inside json message of TA %s error, %v", str_taId, err)
		return nil, err
	}

	//TODO: use sessionKey to encrypt jsonRetMessage
	encRetMessage, err := aesGCMEncrypt(sessionKey, jsonRetMessage)
	if err != nil{
		logger.L.Sugar().Errorf("Encode return message(json format) of TA %s after get key, error, %v", str_taId, err)
		return nil, err
	}

	//TODO: pack encrypted encRetMessage and encSessionKey as struct
	finalMessage := tagCmdData {
		Key:		encSessionKey,
		EncCmdData:	encRetMessage,
	}

	//TODO encrypt the struct to json format
	finalRetMessage, err := json.Marshal(finalMessage)
	if err != nil{
		logger.L.Sugar().Errorf("Encode outside json message of TA %s error, %v", str_taId, err)
		return nil, err
	}

	return finalRetMessage, nil
}

func DecryptKeyOpIncome(encCmdData []byte)(inKeyInfo, error){
	var cmdData tagCmdData
	var message inKeyInfo
	err := json.Unmarshal(encCmdData, &cmdData)
	if err != nil {
		logger.L.Sugar().Errorf("Decode outside json of TA error, %v", err)
		return message, err
	}

	// TODO: get kcm private key(kcm private key is a global variable now)

	// TODO: use kcm private key to decode key
	decKey := RsaDecrypt(cmdData.Key, privKey)

	// TODO: use decoded key to decode cmdData.encCmdData and save the result in encMessage
	encMessage, err := aesGCMDecrypt(decKey, cmdData.EncCmdData)	// Encrypt algorithm: AES GCM (256bit) (AES256GCM)
	if err != nil {
		logger.L.Sugar().Errorf("Decode AESGCM error, %v", err)
		return message, err
	}

	err = json.Unmarshal(encMessage, &message)
	if err != nil {
		logger.L.Sugar().Errorf("Decode inside json of TA error, %v", err)
		return message, err
	}

	return message, nil
}
