package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"github.com/spf13/pflag"
)

const (
	raagentVersion = "version 0.1.0"
)

func init() {
	config.InitRacFlags()
}

func main() {
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	pflag.Parse()
	if *config.RacVersionFlag {
		fmt.Printf("remote attestation client(raagent): %s\n", raagentVersion)
		return
	}
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

	// assume tpm chip has an Ek from tpm2.CreatePrimary and its EC is stored in
	// NVRAM. So in test mode, create EK and sign it from PCA, save it to NVRAM
	tpm.GenerateEKey()
	generateEKeyCert(tpm)
	tpm.LoadEKeyCert()
	loadIKCert(tpm)

	// step 2. if rac doesn't have clientId, uses EC and ikPub to sign
	// a IC and do the register process.
	if cid <= 0 {
		cid = registerClientID(tpm)
	}
	config.Save()

	if testMode {
		tpm.PreparePCRsTest()
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

// generateEKeyCert gets the EK public from tpm simulator and sends to PCA
// to sign it, after that saves it into NVRAM, like manufactory did.
func generateEKeyCert(t *ractools.TPM) {
	cfg := config.GetDefault(config.ConfClient)
	testMode := cfg.GetTestMode()
	if testMode {
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
		t.DefineNVRAM(ractools.IndexRsa2048EKCert, uint16(len(cfg.GetEKeyCertTest())))
		t.WriteNVRAM(ractools.IndexRsa2048EKCert, cfg.GetEKeyCertTest())
	}
}

func loadIKCert(t *ractools.TPM) error {
	cfg := config.GetDefault(config.ConfClient)
	if cfg.GetIKeyCert() != nil {
		return t.LoadIKey()
	}
	t.GenerateIKey()
	ikPubDer, err := x509.MarshalPKIXPublicKey(t.IK.Pub)
	if err != nil {
		log.Fatal("Client: can't get Ik public der data")
	}
	reqIC := clientapi.GenerateIKCertRequest{
		EkCert: cfg.GetEKeyCert(),
		IkPub:  ikPubDer,
		IkName: t.IK.Name,
	}
	server := cfg.GetServer()
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
	if cfg.GetTestMode() {
		cfg.SetIKeyCertTest(icDer)
	}
	cfg.SetIKeyCert(icDer)
	return nil
}

func registerClientID(t *ractools.TPM) int64 {
	cfg := config.GetDefault(config.ConfClient)
	testMode := cfg.GetTestMode()
	server := cfg.GetServer()
	var icDer []byte
	if testMode {
		icDer = cfg.GetIKeyCert()
	} else {
		icDer = cfg.GetIKeyCert()
	}
	clientInfo, err := ractools.GetClientInfo(!testMode)
	if err != nil {
		log.Fatalf("Client: GetClientInfo failed, error: %v", err)
	}
	bk, err := clientapi.DoRegisterClient(server, &clientapi.RegisterClientRequest{
		Ic:         &clientapi.Cert{Cert: icDer},
		ClientInfo: &clientapi.ClientInfo{ClientInfo: clientInfo},
	})
	if err != nil {
		log.Fatal("Client: can't register rac!")
	}
	cid := bk.GetClientId()
	cc := bk.GetClientConfig()
	cfg.SetClientId(cid)
	cfg.SetDigestAlgorithm(cc.GetDigestAlgorithm())
	t.SetDigestAlg(cc.GetDigestAlgorithm())
	cfg.SetHBDuration(time.Duration(cc.GetHbDurationSeconds() * int64(time.Second)))
	cfg.SetTrustDuration(time.Duration(cc.GetTrustDurationSeconds() * int64(time.Second)))
	return cid
}

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
	cfg.SetHBDuration(time.Duration(conf.GetHbDurationSeconds() * int64(time.Second)))
	cfg.SetTrustDuration(time.Duration(conf.GetTrustDurationSeconds() * int64(time.Second)))
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
	if srr.GetResult() {
		log.Printf("Client: send a new trust report to RAS ok.")
	} else {
		log.Printf("Client: send a new trust report to RAS failed.")
	}
}
