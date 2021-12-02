package main

import (
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"github.com/spf13/pflag"
)

func init() {
	config.InitRacFlags()
}

func main() {
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	pflag.Parse()
	cfg := config.GetDefault(config.ConfClient)
	testMode := cfg.GetTestMode()
	server := cfg.GetServer()
	cid := cfg.GetClientId()
	tpm, err := ractools.OpenTPM(!testMode)
	if err != nil {
		log.Printf("OpenTPM failed, error: %s \n", err)
		return
	}
	defer tpm.Close()
	//the input is not be used now
	//TODO: add tpm config file
	tpm.Prepare(&ractools.TPMConfig{}, server, generateEKCert)

	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	if cid < 0 {
		ekCert, err := tpm.GetEKCert()
		if err != nil {
			log.Printf("GetEkCert failed, error: %s \n", err)
		}

		req := clientapi.CreateIKCertRequest{
			EkCert: string(ekCert),
			IkPub:  string(tpm.GetIKPub()),
			IkName: tpm.GetIKName(),
		}
		bkk, err := clientapi.DoCreateIKCert(server, &req)
		if err != nil {
			log.Fatal("Client:can't Create IkCert")
		}

		ic, err := tpm.ActivateIKCert(&ractools.IKCertInput{
			CredBlob:        bkk.CredBlob,
			EncryptedSecret: bkk.EncryptedSecret,
			EncryptedCert:   bkk.EncryptedIC,
			DecryptAlg:      bkk.EncryptAlg,
			DecryptParam:    bkk.EncryptParam,
		})
		if err != nil {
			log.Fatalf("Client: ActivateIKCert failed, error: %v", err)
		}

		clientInfo, err := ractools.GetClientInfo(!testMode)
		if err != nil {
			log.Fatalf("Client: GetClientInfo failed, error: %v", err)
		}
		bk, err := clientapi.DoRegisterClient(server, &clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: ic},
			ClientInfo: &clientapi.ClientInfo{ClientInfo: clientInfo},
		})
		if err != nil {
			log.Fatal("Client: can't register rac!")
		}
		cid = bk.GetClientId()
		cfg.SetClientId(cid)
		cfg.SetHBDuration(time.Duration((int64)(time.Second) * bk.GetClientConfig().HbDurationSeconds))
		log.Printf("Client: get clientId=%d", cid)
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

// Generate EKCert through grpc call clientapi.DoGenerateEKCert
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
				Algorithm: tRep.PcrInfo.AlgName,
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
