package main

import (
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

func main() {
	const addr string = "127.0.0.1:40001"
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.

	//akname,_,akpub,err:=ractools.CreateAk(rw,parentHandle,"",ractools.MyPassword,ractools.PcrSelection1_17)
	req := clientapi.CreateIKCertRequest{
		EkPub: nil,
		IkPub: nil,
		IkName: nil,
	}
	bk,err := clientapi.DoCreateIKCert(addr,&req)
	if err !=nil{
		log.Fatal("Client:can't Create IkCert")
	}
	eic := bk.GetIcEncrypted()
	log.Println("Client:get encryptedIC=",eic)
	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	cid := int64(-1)
	if cid == -1 {
		bk, err := clientapi.DoRegisterClient(addr, &clientapi.RegisterClientRequest{})
		if err != nil {
			log.Fatal("Client: can't register rac!")
		}
		cid = bk.GetClientId()
		log.Printf("Client: get clientId=%d", cid)
	}

	// step 3. if rac has clientId, it uses clientId to send heart beat.
	for {
		bk, err := clientapi.DoSendHeartbeat(addr, &clientapi.SendHeartbeatRequest{ClientId: cid})
		if err != nil {
			log.Fatalf("Client: send heart beat error %v", err)
		}
		log.Printf("Client: get heart beat back %v", bk.GetNextAction())

		// step 4. do what ras tells to do by NextAction...

		// step 5. what else??

		// step n. sleep and wait.
		time.Sleep(time.Second * 3)
	}
}
