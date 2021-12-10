package main

import (
	"crypto/x509"
	"log"
	"os"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/spf13/pflag"
)

func init() {
	config.InitRacFlags()
}

func main() {
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	pflag.Parse()
	cfg := config.GetDefault(config.ConfClient)
	config.SetupSignalHandler()
	testMode := cfg.GetTestMode()
	server := cfg.GetServer()
	cid := cfg.GetClientId()
	tpmConf := ractools.TPMConfig{}
	if testMode {
		tpmConf.IMALogPath = ractools.TestImaLogPath
		tpmConf.BIOSLogPath = ractools.TestBiosLogPath
		tpmConf.ReportHashAlg = ""
	} else {
		tpmConf.IMALogPath = ractools.ImaLogPath
		tpmConf.BIOSLogPath = ractools.BiosLogPath
		tpmConf.ReportHashAlg = ""
	}
	tpm, err := ractools.OpenTPM(!testMode, &tpmConf)
	if err != nil {
		log.Printf("OpenTPM failed, error: %s\n", err)
		os.Exit(1)
	}
	defer tpm.Close()

	// in test mode, create EK, generate EC from PCA and save it in NVRAM
	if testMode {
		generateECForTest(tpm)
	}

	// step 2. if rac doesn't have clientId, uses EC and ikPub to sign
	// a IC and do the register process.
	if cid <= 0 {
		cid = getICAndDoRegister(tpm)
		cfg.SetClientId(cid)
		//cfg.SetHBDuration(time.Duration((int64)(time.Second) * bk.GetClientConfig().HbDurationSeconds))
		config.Save()
	}

	// step 3. if rac has clientId, it uses clientId to send heart beat.
	for {
		rpy, err := clientapi.DoSendHeartbeat(server, &clientapi.SendHeartbeatRequest{ClientId: cid})
		if err != nil {
			log.Fatalf("Client: send heart beat error %v", err)
		}
		log.Printf("Client: get heart beat back %v", rpy.GetNextAction())

		// step 4. do what ras tells to do by NextAction...
		DoNextAction(tpm, server, cid, rpy)

		// step 5. what else??

		// step n. sleep and wait.
		time.Sleep(cfg.GetHBDuration())
	}
}

func generateECForTest(t *ractools.TPM) {
	cfg := config.GetDefault(config.ConfClient)
	t.GenerateEPubKeyTest()
	if cfg.GetEKeyCertTest() == nil {
		ekPubDer, err := x509.MarshalPKIXPublicKey(t.EK.Pub)
		if err != nil {
			log.Fatal("Client: can't get Ek public der data")
		}
		server := cfg.GetServer()
		reqEC := clientapi.GenerateEKCertRequest{
			EkPub: ekPubDer,
		}
		rspEC, err := clientapi.DoGenerateEKCert(server, &reqEC)
		if err != nil {
			log.Fatal("Client: can't Create EkCert")
		}
		cfg.SetEKeyCertTest(rspEC.EkCert)
	}
	t.DefineNVRAM(ractools.IndexRsa2048EKCert, uint16(len(cfg.GetEKeyCertBytesTest())))
	t.WriteNVRAM(ractools.IndexRsa2048EKCert, cfg.GetEKeyCertBytesTest())
}

func getICAndDoRegister(t *ractools.TPM) int64 {
	cfg := config.GetDefault(config.ConfClient)
	server := cfg.GetServer()
	t.GenerateIPrivKeyTest()
	ikPubDer, err := x509.MarshalPKIXPublicKey(t.IK.Pub)
	if err != nil {
		log.Fatal("Client: can't get Ik public der data")
	}
	reqIC := clientapi.GenerateIKCertRequest{
		EkCert: cfg.GetEKeyCertBytesTest(),
		IkPub:  ikPubDer,
		IkName: t.IK.Name,
	}
	rspIC, err := clientapi.DoGenerateIKCert(server, &reqIC)
	if err != nil {
		log.Fatal("Client: can't Create IkCert")
	}
	icDer, err := t.ActivateIKCert(&ractools.IKCertInput{
		CredBlob:        rspIC.CredBlob,
		EncryptedSecret: rspIC.EncryptedSecret,
		EncryptedCert:   rspIC.EncryptedIC,
		DecryptAlg:      rspIC.EncryptAlg,
		DecryptParam:    rspIC.EncryptParam,
	})
	if err != nil {
		log.Fatalf("Client: ActivateIKCert failed, error: %v", err)
	}
	icPem, _ := pca.EncodeKeyCertToPEM(icDer)
	clientInfo, err := ractools.GetClientInfo(!cfg.GetTestMode())
	if err != nil {
		log.Fatalf("Client: GetClientInfo failed, error: %v", err)
	}
	bk, err := clientapi.DoRegisterClient(server, &clientapi.RegisterClientRequest{
		Ic:         &clientapi.Cert{Cert: icPem},
		ClientInfo: &clientapi.ClientInfo{ClientInfo: clientInfo},
	})
	if err != nil {
		log.Fatal("Client: can't register rac!")
	}
	cid := bk.GetClientId()
	return cid
}

// Generate EKCert through grpc call clientapi.DoGenerateEKCert
/*
func generateEKCert(ekPub []byte, server string) ([]byte, error) {
	req := clientapi.GenerateEKCertRequest{
		EkPub: ekPub,
	}
	bk, err := clientapi.DoGenerateEKCert(server, &req)
	if err != nil {
		return nil, err
	}
	return bk.EkCert, nil
}
*/

// DoNextAction checks the nextAction field and invoke the corresponding handler function.
func DoNextAction(tpm *ractools.TPM, srv string, id int64, rpy *clientapi.SendHeartbeatReply) {
	action := rpy.GetNextAction()
	if (action & cache.CMDSENDCONF) == cache.CMDSENDCONF {
		SetNewConf(rpy)
	}
	if (action & cache.CMDGETREPORT) == cache.CMDGETREPORT {
		SendTrustReport(tpm, srv, id, rpy)
	}
	// add new command handler functions here.
}

// SetNewConf sets the new configuration values from RAS.
func SetNewConf(rpy *clientapi.SendHeartbeatReply) {
	log.Printf("Client: get new configuration from RAS.")
	cfg := config.GetDefault(config.ConfClient)
	conf := rpy.GetActionParameters().GetClientConfig()
	cfg.SetHBDuration(time.Duration(conf.HbDurationSeconds))
	cfg.SetTrustDuration(time.Duration(conf.TrustDurationSeconds))
}

// SendTrustReport sneds a new trust report to RAS.
func SendTrustReport(tpm *ractools.TPM, srv string, id int64, rpy *clientapi.SendHeartbeatReply) {
	cfg := config.GetDefault(config.ConfClient)
	tRep, err := tpm.GetTrustReport(rpy.GetActionParameters().GetNonce(), id)
	if err != nil {
		log.Printf("Client: create a new trust report failed :%v", err)
	} else {
		log.Printf("Client: create a new trust report success")
	}
	var manifest []*clientapi.Manifest
	for _, m := range tRep.Manifest {
		manifest = append(manifest, &clientapi.Manifest{Type: m.Type, Item: m.Content})
	}

	srr, _ := clientapi.DoSendReport(srv, &clientapi.SendReportRequest{
		ClientId: id,
		TrustReport: &clientapi.TrustReport{
			PcrInfo: &clientapi.PcrInfo{
				Algorithm: cfg.GetDigestAlgorithm(),
				PcrValues: (map[int32]string)(tRep.PcrInfo.Values),
				PcrQuote: &clientapi.PcrQuote{
					Quoted:    tRep.PcrInfo.Quote.Quoted,
					Signature: tRep.PcrInfo.Quote.Signature,
				},
			},
			ClientId: tRep.ClientID,
			ClientInfo: &clientapi.ClientInfo{
				ClientInfo: tRep.ClientInfo,
			},
			Manifest: manifest,
		},
	})
	if srr.Result {
		log.Printf("Client: send a new trust report to RAS ok.")
	} else {
		log.Printf("Client: send a new trust report to RAS failed.")
	}
}
