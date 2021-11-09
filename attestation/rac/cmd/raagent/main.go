package main

import (
	"encoding/json"
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

func main() {
	const addr string = "127.0.0.1:40001"
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	cid := config.GetDefault().GetClientId()
	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	if cid <= 0 {
		ak, _, err := ractools.GetAk()

		req := clientapi.CreateIKCertRequest{
			EkCert: ractools.CertPEM,
			IkPub:  ractools.PubPEM,
			IkName: ak.Name,
		}
		bkk, err := clientapi.DoCreateIKCert(addr, &req)
		if err != nil {
			log.Fatal("Client:can't Create IkCert")
		}
		eic := bkk.GetIcEncrypted()
		log.Println("Client:get encryptedIC=", eic)

		ci, err := json.Marshal(map[string]string{"test name": "test value"})
		bk, err := clientapi.DoRegisterClient(addr, &clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: []byte{1, 2}},
			ClientInfo: &clientapi.ClientInfo{ClientInfo: string(ci)},
		})
		if err != nil {
			log.Fatal("Client: can't register rac!")
		}
		cid = bk.GetClientId()
		config.GetDefault().SetClientId(cid)
		config.GetDefault().SetHBDuration(time.Duration((int64)(time.Second) * bk.GetClientConfig().HbDurationSeconds))
		log.Printf("Client: get clientId=%d", cid)
		config.Save()
	}

	// step 3. if rac has clientId, it uses clientId to send heart beat.
	for {
		rpy, err := clientapi.DoSendHeartbeat(addr, &clientapi.SendHeartbeatRequest{ClientId: cid})
		if err != nil {
			log.Fatalf("Client: send heart beat error %v", err)
		}
		log.Printf("Client: get heart beat back %v", rpy.GetNextAction())

		// step 4. do what ras tells to do by NextAction...
		DoNextAction(addr, cid, rpy)

		// step 5. what else??

		// step n. sleep and wait.
		time.Sleep(config.GetDefault().GetHBDuration())
	}
}

// DoNextAction checks the nextAction field and invoke the corresponding handler function.
func DoNextAction(srv string, id int64, rpy *clientapi.SendHeartbeatReply) {
	action := rpy.GetNextAction()
	if (action & cache.CMDSENDCONF) == cache.CMDSENDCONF {
		SetNewConf(srv, id, rpy)
	}
	if (action & cache.CMDGETREPORT) == cache.CMDGETREPORT {
		SendTrustReport(srv, id, rpy)
	}
	// add new command handler functions here.
}

// SetNewConf sets the new configuration values from RAS.
func SetNewConf(srv string, id int64, rpy *clientapi.SendHeartbeatReply) {
	log.Printf("Client: get new configuration from RAS.")
	config.GetDefault().SetHBDuration(time.Duration(rpy.GetActionParameters().GetClientConfig().HbDurationSeconds))
	config.GetDefault().SetTrustDuration(time.Duration(rpy.GetActionParameters().GetClientConfig().TrustDurationSeconds))
}

// SendTrustReport sneds a new trust report to RAS.
func SendTrustReport(srv string, id int64, rpy *clientapi.SendHeartbeatReply) {
	_, err := ractools.GetTrustReport(ractools.TrustReportIn{
		Nonce:      rpy.GetActionParameters().GetNonce(),
		ClientId:   id,
		ClientInfo: "",
	})
	if err != nil {
		log.Fatalf("Client: create a new trust report failed :%v", err)
		return
	}

	srr, _ := clientapi.DoSendReport(srv, &clientapi.SendReportRequest{
		ClientId:    id,
		TrustReport: &clientapi.TrustReport{},
	})
	if srr.Result {
		log.Printf("Client: send a new trust report to RAS ok.")
	} else {
		log.Printf("Client: send a new trust report to RAS failed.")
	}
}
