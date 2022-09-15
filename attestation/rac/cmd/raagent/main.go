/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: jiayunhao
Create: 2021-09-17
Description: raagent main package entry.
	1. 2022-01-22	wucaijun
		refine the tpm simulator start process and send trust report process.
*/

// main package for raagent.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

const (
	raagentVersion = "1.1.2"
)

func main() {
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	initFlags()
	loadConfigs()
	handleFlags()
	signalHandler()

	logger.L.Debug("open tpm...")
	tpmConf := createTPMConfig(GetTestMode(), GetImaLogPath(), GetBiosLogPath(), GetDigestAlgorithm())
	if GetTestMode() && GetSeed() == -1 {
		random, err0 := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		if err0 != nil {
			logger.L.Sugar().Errorf("Client: generate seed failed, error: %s", err0)
			os.Exit(2)
		}
		SetSeed(random.Int64())
	}
	err := ractools.OpenTPM(!GetTestMode(), tpmConf, GetSeed())
	if err != nil {
		logger.L.Sugar().Errorf("open tpm failed, %s", err)
		os.Exit(1)
	}
	defer ractools.CloseTPM()
	logger.L.Debug("open tpm success")

	prepare()

	// step 3. if rac has clientId, it uses clientId to send heart beat.
	loop()
}

func prepareEK(ras *clientapi.RasConn) {
	logger.L.Debug("generate EK...")
	err := ractools.GenerateEKey()
	if err != nil {
		logger.L.Sugar().Errorf("generate EK failed, %s", err)
	}
	logger.L.Debug("generate EK success")

	logger.L.Debug("load EK certificate...")
	if !GetTestMode() && racCfg.eKeyCert == nil {
		err = LoadEKeyCert()
		if err != nil {
			logger.L.Sugar().Errorf("load EK certificate failed, %s", err)
		}
	}
	if GetEKeyCert() == nil || len(GetEKeyCert()) == 0 {
		generateEKeyCert(ras)
	}
	logger.L.Debug("load EK certificate success")
}

func prepareIK(ras *clientapi.RasConn) {
	logger.L.Debug("load IK certificate...")
	err := ractools.GenerateIKey()
	if err != nil {
		logger.L.Sugar().Errorf("generate IK failed, %s", err)
	}
	if GetIKeyCert() == nil || len(GetIKeyCert()) == 0 {
		generateIKeyCert(ras)
	}
	logger.L.Debug("load IK certificate success")
}

func prepare() {
	ras, err := clientapi.CreateConn(GetServer())
	if err != nil {
		logger.L.Sugar().Errorf("connect ras server fail, %s", err)
		os.Exit(3)
	}
	defer clientapi.ReleaseConn(ras)
	// set digest algorithm

	// assume tpm chip has an Ek from tpm2.CreatePrimary and its EC is stored in
	// NVRAM. So in test mode, create EK and sign it from PCA, save it to NVRAM
	prepareEK(ras)
	prepareIK(ras)

	// step 2. if rac doesn't have clientId, uses EC and ikPub to sign
	// a IC and do the register process.
	id := GetClientId()
	for id <= 0 {
		id = registerClientID(ras)
		if id > 0 {
			SetClientId(id)
			logger.L.Sugar().Debugf("get client id %d success", id)
		} else {
			logger.L.Debug("get client id fail, try again...")
			time.Sleep(2 * time.Second)
		}
	}
	logger.L.Sugar().Debugf("register client success, clientID=%d ", id)
	saveConfigs()
	err = ractools.SetDigestAlg(GetDigestAlgorithm())
	if err != nil {
		logger.L.Sugar().Errorf("set digest algorithm, %s", err)
	}
	err = ractools.PreparePCRsTest()
	if err != nil {
		logger.L.Sugar().Errorf("prepare PCRs failed, %s", err)
	}
}

func loop() {
	for {
		logger.L.Debug("send heart beat...")
		ras, err := clientapi.CreateConn(GetServer())
		if err != nil {
			logger.L.Sugar().Errorf("connect ras server fail, %s", err)
			time.Sleep(10 * time.Second)
			continue
		}
		rpy, err := clientapi.DoSendHeartbeatWithConn(ras,
			&clientapi.SendHeartbeatRequest{ClientId: GetClientId()})
		if err == nil {
			logger.L.Debug("send heart beat ok")
			// step 4. do what ras tells client to do by NextAction...
			doNextAction(ras, rpy)
		}
		clientapi.ReleaseConn(ras)
		time.Sleep(GetHBDuration())
	}
}

func createTPMConfig(testMode bool, imaLogPath, biosLogPath string, hashAlg string) *ractools.TPMConfig {
	tpmConf := ractools.TPMConfig{}
	if testMode {
		tpmConf.IMALogPath = imaLogPath
		tpmConf.BIOSLogPath = biosLogPath
		tpmConf.ReportHashAlg = hashAlg
		tpmConf.SeedPath = ractools.TestSeedPath
	} else {
		tpmConf.IMALogPath = ractools.ImaLogPath
		tpmConf.BIOSLogPath = ractools.BiosLogPath
		tpmConf.ReportHashAlg = hashAlg
	}
	return &tpmConf
}

func generateEKeyCert(ras *clientapi.RasConn) {
	ekPubDer, err := x509.MarshalPKIXPublicKey(ractools.GetEKPub())
	if err != nil {
		logger.L.Sugar().Errorf("can't get Ek public der data, %v", err)
		return
	}
	reqEC := clientapi.GenerateEKCertRequest{
		EkPub: ekPubDer,
	}
	rspEC, err := clientapi.DoGenerateEKCertWithConn(ras, &reqEC)
	if err != nil {
		logger.L.Sugar().Errorf("can't Create EkCert, %v", err)
		return
	}
	if len(rspEC.EkCert) > 0 {
		SetEKeyCert(rspEC.EkCert)
	}
}

// LoadEKeyCert reads ek certificate from NVRAM
func LoadEKeyCert() error {
	ekCertDer, err := ractools.ReadNVRAM(ractools.IndexRsa2048EKCert)
	if err != nil {
		logger.L.Sugar().Errorf("can't read Ek Cert der data, %v", err)
		return err
	}
	// There is an extra zero sequence behind the physical tpm certificate,
	// which should be removed, otherwise the certificate parsing will be wrong.
	for i := range ekCertDer {
		if ekCertDer[i] == 0 && ekCertDer[i+1] == 0 {
			ekCertDer = ekCertDer[:i]
			break
		}
	}
	SetEKeyCert(ekCertDer)
	return nil
}

// generateIKeyCert gets the IK public from tpm simulator and sends to PCA
// to sign it, after that saves it into config.
func generateIKeyCert(ras *clientapi.RasConn) {
	ikCert := GetIKeyCert()
	if ikCert != nil && len(GetIKeyCert()) != 0 {
		return
	}
	ikPubDer, err := x509.MarshalPKIXPublicKey(ractools.GetIKPub())
	if err != nil {
		logger.L.Sugar().Errorf("can't get Ik public der data, %v", err)
		return
	}
	reqIC := clientapi.GenerateIKCertRequest{
		EkCert: GetEKeyCert(),
		IkPub:  ikPubDer,
		IkName: ractools.GetIKName(),
	}
	rspIC, err := clientapi.DoGenerateIKCertWithConn(ras, &reqIC)
	if err != nil {
		logger.L.Sugar().Errorf("can't Create IkCert, %v", err)
		return
	}
	icDer, err := ractools.ActivateIKCert(&ractools.IKCertInput{
		CredBlob:        rspIC.CredBlob,
		EncryptedSecret: rspIC.EncryptedSecret,
		EncryptedCert:   rspIC.EncryptedIC,
		DecryptAlg:      rspIC.EncryptAlg,
		DecryptParam:    rspIC.EncryptParam,
	})
	if err != nil {
		logger.L.Sugar().Errorf("activateIKCert failed, %v", err)
		return
	}
	SetIKeyCert(icDer)
}

func registerClientID(ras *clientapi.RasConn) int64 {
	icDer := GetIKeyCert()
	clientInfo, err := ractools.GetClientInfo()
	if err != nil {
		logger.L.Sugar().Errorf("GetClientInfo failed, %v", err)
	}
	bk, err := clientapi.DoRegisterClientWithConn(ras,
		&clientapi.RegisterClientRequest{
			Cert:       icDer,
			ClientInfo: clientInfo,
		})
	if err != nil {
		logger.L.Sugar().Errorf("can't register rac, %v", err)
		return -1
	}
	cid := bk.GetClientId()
	cc := bk.GetClientConfig()
	SetClientId(cid)
	SetDigestAlgorithm(cc.GetDigestAlgorithm())
	err = ractools.SetDigestAlg(cc.GetDigestAlgorithm())
	if err != nil {
		logger.L.Sugar().Errorf("can't register rac, %v", err)
		return -1
	}
	SetHBDuration(time.Duration(cc.GetHbDurationSeconds() * int64(time.Second)))
	SetTrustDuration(time.Duration(cc.GetTrustDurationSeconds() * int64(time.Second)))
	return cid
}

// doNextAction checks the nextAction field and invoke the corresponding handler function.
func doNextAction(ras *clientapi.RasConn, rpy *clientapi.SendHeartbeatReply) {
	actions := rpy.GetNextAction()
	if (actions & typdefs.CmdSendConfig) == typdefs.CmdSendConfig {
		setNewConf(rpy)
	}
	if (actions & typdefs.CmdGetReport) == typdefs.CmdGetReport {
		sendTrustReport(ras, rpy)
	}
	// add new command handler functions here.
}

// setNewConf sets the new configuration values from RAS.
func setNewConf(rpy *clientapi.SendHeartbeatReply) {
	logger.L.Debug("save new configuration from ras")
	conf := rpy.GetClientConfig()
	SetHBDuration(time.Duration(conf.GetHbDurationSeconds() * int64(time.Second)))
	SetTrustDuration(time.Duration(conf.GetTrustDurationSeconds() * int64(time.Second)))
	SetDigestAlgorithm(conf.GetDigestAlgorithm())
	err := ractools.SetDigestAlg(GetDigestAlgorithm())
	if err != nil {
		logger.L.Sugar().Errorf("can't set new digest algorithm, %v", err)
	}
	saveConfigs()
}

// sendTrustReport sneds a new trust report to RAS.
func sendTrustReport(ras *clientapi.RasConn, rpy *clientapi.SendHeartbeatReply) {
	tRep, err := ractools.GetTrustReport(GetClientId(),
		rpy.GetClientConfig().GetNonce(), GetDigestAlgorithm())
	if err != nil {
		logger.L.Sugar().Errorf("prepare trust report failed, %v", err)
		return
	}
	// handle clientInfo
	ci := tRep.ClientInfo
	ciMap := map[string]string{}
	err = json.Unmarshal([]byte(ci), &ciMap)
	if err != nil {
		logger.L.Sugar().Errorf("unmarshal client info failed, %v", err)
		return
	}
	ciMap[typdefs.DigestAlgStr] = GetDigestAlgorithm()
	newCi, err := json.Marshal(ciMap)
	if err != nil {
		logger.L.Sugar().Errorf("marshal client info failed, %v", err)
		return
	}
	tRep.ClientInfo = string(newCi)

	var manifests []*clientapi.Manifest
	for _, m := range tRep.Manifests {
		manifests = append(manifests,
			&clientapi.Manifest{Key: m.Key, Value: m.Value})
	}
	clientapi.DoSendReportWithConn(ras,
		&clientapi.SendReportRequest{
			ClientId:   tRep.ClientID,
			Nonce:      tRep.Nonce,
			ClientInfo: tRep.ClientInfo,
			Quoted:     tRep.Quoted,
			Signature:  tRep.Signature,
			Manifests:  manifests,
		})
	logger.L.Debug("send trust report ok")
}
