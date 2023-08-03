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
package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kcmstools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
)

const (
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

type rasService struct {
	clientapi.UnimplementedRasServer
}

type tagCmdData struct {
	Key        string
	EncCmdData string
}

type inKeyInfo struct {
	TAId      string
	Account   string
	Password  string
	KeyId     string
	HostKeyId string
	Command   uint32
	KTAId     string
}

type retKeyInfo struct {
	TAId      string
	KeyId     string
	PlainText string
	HostKeyId string
	Command   uint32
}

var (
	srv *grpc.Server = nil
)

func getSockNum() int {
	pid := os.Getpid()
	limits := fmt.Sprintf("/proc/%d/limits", pid)
	err := ioutil.WriteFile(strGetName, []byte(strGetSh), 0755)
	if err != nil {
		return -1
	}
	out, err := exec.Command(strGetName, limits).Output()
	if err != nil {
		return -1
	}
	totalStr := strings.Trim(string(out), strSpaceLine)
	totalNum, err := strconv.Atoi(totalStr)
	if err != nil {
		return -1
	}
	sockNum := totalNum * 9 / 10
	if totalNum-sockNum < 50 {
		sockNum = totalNum - 50
	}
	err1 := os.Remove(strGetName)
	if err1 != nil {
		return -1
	}
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
	clientapi.RegisterRasServer(srv, newRasService())
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
func (s *rasService) GenerateEKCert(ctx context.Context, in *clientapi.GenerateEKCertRequest) (*clientapi.GenerateEKCertReply, error) {
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
	return &clientapi.GenerateEKCertReply{EkCert: ekCert}, nil
}

// GenerateIKCert handles the generation of the IK certificate for client.
func (s *rasService) GenerateIKCert(ctx context.Context, in *clientapi.GenerateIKCertRequest) (*clientapi.GenerateIKCertReply, error) {
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
	return &clientapi.GenerateIKCertReply{
		EncryptedIC:     encIkCert.EncryptedCert,
		CredBlob:        encIkCert.SymKeyParams.CredBlob,
		EncryptedSecret: encIkCert.SymKeyParams.EncryptedSecret,
		EncryptAlg:      encIkCert.SymKeyParams.EncryptAlg,
		EncryptParam:    encIkCert.SymKeyParams.EncryptParam,
	}, nil
}

// RegisterClient registers a new client by IK certificate and its client information string.
func (s *rasService) RegisterClient(ctx context.Context, in *clientapi.RegisterClientRequest) (*clientapi.RegisterClientReply, error) {
	registered := false
	if config.GetMgrStrategy() == config.AutoStrategy {
		registered = true
	}
	ikDer := in.GetCert()
	ikPem, err := cryptotools.EncodeKeyCertToPEM(ikDer)
	if err != nil {
		logger.L.Sugar().Errorf("encode IK Cert to PEM fail, %v", err)
		return &clientapi.RegisterClientReply{ClientId: -1}, err
	}
	client, err := trustmgr.RegisterClientByIK(string(ikPem), in.GetClientInfo(), registered)
	if err != nil {
		logger.L.Sugar().Errorf("register client fail, %v", err)
		return &clientapi.RegisterClientReply{ClientId: -1}, err
	}
	return &clientapi.RegisterClientReply{
		ClientId: client.ID,
		ClientConfig: &clientapi.ClientConfig{
			HbDurationSeconds:    int64(config.GetHBDuration().Seconds()),
			TrustDurationSeconds: int64(config.GetTrustDuration().Seconds()),
			Nonce:                0,
			DigestAlgorithm:      config.GetDigestAlgorithm(),
		},
	}, nil
}

// UnregisterClient unregisters a client from cache and database, reserved its database record and files.
func (s *rasService) UnregisterClient(
	ctx context.Context,
	in *clientapi.UnregisterClientRequest) (*clientapi.UnregisterClientReply, error) {
	cid := in.GetClientId()
	trustmgr.UnRegisterClientByID(cid)
	return &clientapi.UnregisterClientReply{Result: true}, nil
}

// SendHeartbeat sends heart beat message to ras and get next action back.
func (s *rasService) SendHeartbeat(ctx context.Context, in *clientapi.SendHeartbeatRequest) (*clientapi.SendHeartbeatReply, error) {
	var out clientapi.SendHeartbeatReply
	cid := in.GetClientId()
	cmds, nonce := trustmgr.HandleHeartbeat(cid)
	if cmds == typdefs.CmdNone {
		out = clientapi.SendHeartbeatReply{
			NextAction: cmds,
		}
	} else {
		out = clientapi.SendHeartbeatReply{
			NextAction: cmds,
			ClientConfig: &clientapi.ClientConfig{
				HbDurationSeconds:    int64(config.GetHBDuration().Seconds()),
				TrustDurationSeconds: int64(config.GetTrustDuration().Seconds()),
				Nonce:                nonce,
				DigestAlgorithm:      config.GetDigestAlgorithm(),
			},
		}
	}
	return &out, nil
}

// SendReport saves the trust report from client into database/files and verifies it.
func (s *rasService) SendReport(ctx context.Context, in *clientapi.SendReportRequest) (*clientapi.SendReportReply, error) {
	cid := in.GetClientId()
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
	_, err := trustmgr.ValidateReport(&trustReport, config.GetTestMode())
	if err != nil {
		logger.L.Sugar().Errorf("validate client(%d) report error, %v", cid, err)
		return &clientapi.SendReportReply{Result: false}, nil
	}

	err = trustmgr.HandleBaseValue(&trustReport)
	if err != nil {
		logger.L.Sugar().Errorf("handle client(%d) basevalue error, %v", cid, err)
		return &clientapi.SendReportReply{Result: false}, nil
	}
	return &clientapi.SendReportReply{Result: true}, nil
}

// SendKCMPubKeyCert sends kcm public key cert from ras and gets reply message back.
func (s *rasService) SendKCMPubKeyCert(
	ctx context.Context,
	in *clientapi.SendKCMPubKeyCertRequest) (*clientapi.SendKCMPubKeyCertReply, error) {

	kcmPubKeyCert, err := kcmstools.SendKCMPubKeyCert()
	if err != nil {
		logger.L.Sugar().Errorf("Send KCM public key cert error, %v", err)
		return &clientapi.SendKCMPubKeyCertReply{Result: false}, err
	} else {
		out := clientapi.SendKCMPubKeyCertReply{
			Result:        true,
			KcmPubKeyCert: kcmPubKeyCert,
		}
		return &out, nil
	}
}

// VerifyKTAPubKeyCert verifies kta public key cert and gets reply message back.
func (s *rasService) VerifyKTAPubKeyCert(
	ctx context.Context,
	in *clientapi.VerifyKTAPubKeyCertRequest) (*clientapi.VerifyKTAPubKeyCertReply, error) {
	deviceId := in.GetClientId()
	if deviceId == 0 {
		return &clientapi.VerifyKTAPubKeyCertReply{Result: false}, nil
	}

	ktaPem := in.GetKtaPubKeyCert()

	dbConfig := GetdbConfig(strDbConfig)
	kdb.CreateKdbManager(constDB, dbConfig)
	defer kdb.ReleaseKdbManager()

	logger.L.Sugar().Debugf("Going to verify cert of KTA %x", deviceId)
	err := kcmstools.VerifyKTAPubKeyCert(deviceId, ktaPem)
	if err != nil {
		logger.L.Sugar().Errorf("Verify cert of KTA %x error result, %v", deviceId, err)
		return &clientapi.VerifyKTAPubKeyCertReply{Result: false}, err
	} else {
		logger.L.Sugar().Debugf("Have already verified cert of KTA %x", deviceId)
	}
	return &clientapi.VerifyKTAPubKeyCertReply{Result: true}, nil
}

// KeyOperation handles operations releated to key,
// such as generate new key, get key and delete key.
func (s *rasService) KeyOperation(ctx context.Context, in *clientapi.KeyOperationRequest) (*clientapi.KeyOperationReply, error) {
	deviceId := in.GetClientId()
	encCmdData := in.GetEncMessage()
	if len(encCmdData) == 0 {
		return &clientapi.KeyOperationReply{Result: false}, nil
	}

	var message *inKeyInfo
	var sessionKey []byte
	var pubkeycert []byte
	var retMessage retKeyInfo

	privKey, err := kcmstools.ReadCert(certPath + kcmKeyName)
	if privKey == nil {
		logger.L.Sugar().Errorf("private key is nil, %v", err)
		return &clientapi.KeyOperationReply{Result: false}, err
	}
	message, err = DecryptKeyOpIncome(encCmdData, privKey)
	if err != nil {
		logger.L.Sugar().Errorf("Decrypt CmdData error, %v", err)
		return &clientapi.KeyOperationReply{Result: false}, err
	}

	switch message.Command {
	case 0x70000001:
		logger.L.Sugar().Debugf("going to call GenerateNewKey()")
		go kmsServer.ExampleServer()
		defer kmsServer.StopServer()
		dbConfig := GetdbConfig(strDbConfig)
		kdb.CreateKdbManager(constDB, dbConfig)
		defer kdb.ReleaseKdbManager()

		retTAId, key, KtaPublickeyCert, plainText, retKeyId, err := kcmstools.GenerateNewKey(
			[]byte(message.TAId),
			[]byte(message.Account),
			[]byte(message.Password),
			[]byte(message.HostKeyId),
			message.KTAId,
			deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Generate new key of TA %s error, %v", message.TAId, err)
			return &clientapi.KeyOperationReply{Result: false}, err
		}
		logger.L.Sugar().Debugf("get kms supported success")
		retMessage = retKeyInfo{
			TAId:      string(retTAId),
			KeyId:     string(retKeyId),
			PlainText: hex.EncodeToString(plainText),
			HostKeyId: string(message.HostKeyId),
			Command:   message.Command,
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

		retTAId, key, KtaPublickeyCert, plainText, retKeyId, err := kcmstools.GetKey(
			[]byte(message.TAId),
			[]byte(message.Account),
			[]byte(message.Password),
			[]byte(message.KeyId),
			[]byte(message.HostKeyId),
			message.KTAId,
			deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Get key of TA %s error, %v", message.TAId, err)
			return &clientapi.KeyOperationReply{Result: false}, err
		}
		logger.L.Sugar().Debugf("get kms supported success")
		retMessage = retKeyInfo{
			TAId:      string(retTAId),
			KeyId:     string(retKeyId),
			PlainText: string(plainText),
			HostKeyId: message.HostKeyId,
			Command:   message.Command,
		}

		pubkeycert = KtaPublickeyCert
		sessionKey = key

	case 0x70000003:
		logger.L.Sugar().Debugf("going to call DeleteKey()")
		go kmsServer.ExampleServer()
		defer kmsServer.StopServer()
		dbConfig := GetdbConfig(strDbConfig)
		kdb.CreateKdbManager(constDB, dbConfig)
		defer kdb.ReleaseKdbManager()

		key, KtaPublickeyCert, err := kcmstools.DeleteKey(
			[]byte(message.TAId),
			[]byte(message.KeyId),
			message.KTAId,
			deviceId)
		if err != nil {
			logger.L.Sugar().Errorf("Delete key of TA %s error, %v", message.TAId, err)
			return &clientapi.KeyOperationReply{Result: false}, err
		}
		retMessage = retKeyInfo{
			TAId:      message.TAId,
			KeyId:     message.KeyId,
			HostKeyId: message.HostKeyId,
			Command:   message.Command,
		}

		pubkeycert = KtaPublickeyCert
		sessionKey = key

	default:
		logger.L.Sugar().Errorf("resolve command of TA %s failed", message.TAId)
		return &clientapi.KeyOperationReply{Result: false}, err
	}
	logger.L.Sugar().Debugf("get kta trusted success")
	encRetMessage, err := EncryptKeyOpOutcome(retMessage, sessionKey, pubkeycert)
	if err != nil {
		logger.L.Sugar().Errorf("Encode return message of TA %s error, %v", retMessage.TAId, err)
		return &clientapi.KeyOperationReply{Result: false}, err
	}

	out := clientapi.KeyOperationReply{
		Result:        true,
		EncRetMessage: encRetMessage,
	}
	return &out, nil
}

// GetdbConfig returns db config information.
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

// RsaEncrypt is based on rsa algorithm using the key to encrypt data.
func RsaEncrypt(data, keyBytes []byte) ([]byte, error) {
	// 解密pem格式的公钥
	block, _ := pem.Decode(keyBytes)
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.L.Sugar().Errorf("rsa pem decode error, %v", err)
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	// 加密
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		logger.L.Sugar().Errorf("rsa encode error, %v", err)
		return nil, err
	}
	return ciphertext, nil
}

// RsaDecrypt is based on rsa algorithm using the key to decrypt ciphertext.
func RsaDecrypt(ciphertext, keyBytes []byte) ([]byte, error) {
	// 获取私钥
	block, _ := pem.Decode(keyBytes)
	// 解析PKCS1格式的私钥
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

// EncryptKeyOpOutcome firstly encrypt data with sesionkey,
// and then uses kta public key to encrypt sessionkey with kta public key,
// retrurns encrypted data and encrypted sessionkey.
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

	encRetMessage, tag, nonce, err := aesGCMEncrypt(sessionKey, jsonRetMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode return message(json format) of TA %s after get key, error, %v", str_taId, err)
		return nil, err
	}
	appendKey := append(nonce, sessionKey...)
	appendKey = append(appendKey, tag...)

	encSessionKey, err := cryptotools.AsymmetricEncrypt(
		cryptotools.AlgRSA,
		cryptotools.AlgOAEP,
		pubkeycert.PublicKey,
		appendKey,
		nil)
	if err != nil {
		return nil, err
	}

	encKey := hex.EncodeToString(encSessionKey)
	encMessage := hex.EncodeToString(encRetMessage)

	finalMessage := tagCmdData{
		Key:        encKey,
		EncCmdData: encMessage,
	}

	finalRetMessage, err := json.Marshal(finalMessage)
	if err != nil {
		logger.L.Sugar().Errorf("Encode outside json message of TA %s error, %v", str_taId, err)
		return nil, err
	}

	return finalRetMessage, nil
}

// DecryptKeyOpIncome firstly decrypt encrypted session key with kcm privatekey,
// and then uses session key to decrypt encrypted data,
// retrurns decrypted data.
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

	decSessionKey, err := cryptotools.AsymmetricDecrypt(cryptotools.AlgRSA, cryptotools.AlgOAEP, priv, sessionKey, nil)
	if err != nil {
		return nil, err
	}
	nonce := decSessionKey[:12]
	decKey := decSessionKey[12 : len(decSessionKey)-16]
	tag := decSessionKey[len(decSessionKey)-16:]

	appendCmdData := append(decCmdData, tag...)

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
