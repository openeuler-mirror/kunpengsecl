package main

import (
	"fmt"
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

func main() {
	const addr string = "127.0.0.1:40001"
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	cid := config.GetDefaultRac().GetClientId()
	//akname,_,akpub,err:=ractools.CreateAk(rw,parentHandle,"",ractools.MyPassword,ractools.PcrSelection1_17)
	req := clientapi.CreateIKCertRequest{
		EkPub:  nil,
		IkPub:  nil,
		IkName: nil,
	}
	bk, err := clientapi.DoCreateIKCert(addr, &req)
	if err != nil {
		log.Fatal("Client:can't Create IkCert")
	}
	eic := bk.GetIcEncrypted()
	log.Println("Client:get encryptedIC=", eic)
	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	if cid == -1 {
		bk, err := clientapi.DoRegisterClient(addr, &clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: []byte{1, 2}},
			ClientInfo: &clientapi.ClientInfo{ClientInfo: map[string]string{"test name": "test value"}},
		})
		if err != nil {
			log.Fatal("Client: can't register rac!")
		}
		cid = bk.GetClientId()
		config.GetDefaultRac().SetClientId(cid)
		config.GetDefaultRac().SetHBDuration(time.Duration((int64)(time.Second) * bk.GetClientConfig().HbDurationSeconds))
		log.Printf("Client: get clientId=%d", cid)
		config.SaveClient()
	}

	// step 3. if rac has clientId, it uses clientId to send heart beat.
	for {
		bk, err := clientapi.DoSendHeartbeat(addr, &clientapi.SendHeartbeatRequest{ClientId: cid})
		if err != nil {
			log.Fatalf("Client: send heart beat error %v", err)
		}
		log.Printf("Client: get heart beat back %v", bk.GetNextAction())

		// step 4. do what ras tells to do by NextAction...
		/*result := DoNextAction(bk, cid, addr)
		if result {
			log.Printf("do next action ok.")
		} else {
			log.Printf("do next action failed.")
		}*/
		// step 5. what else??

		// step n. sleep and wait.
		time.Sleep(config.GetDefaultRac().GetHBDuration())
	}
}

//具体的动作函数
func ClearCommands(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	return true
}

func SendNewConf(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	fmt.Printf("send new configuration to RAC.")
	return true
}

func GetNewTrurp(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	fmt.Printf("get a new trust report from RAC.")
	rtr, err := ractools.GetTrustReport(nil, ractools.TrustReportIn{})
	srr, _ := clientapi.DoSendReport(*in3.(*string), &clientapi.SendReportRequest{
		ClientId:    *in2.(*int64),
		TrustReport: nil,
	})
	if err != nil {
		log.Fatalf("create a new trust report error!%v", err)
	}
	if srr.Result {
		log.Printf("get a new trust report from RAC ok.%v", rtr)
	} else {
		log.Printf("get a new trust report from RAC failed.")
	}
	return true
}

func SendconfAndGetrep(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	_ = SendNewConf(in1, in2, in3)
	_ = GetNewTrurp(in1, in2, in3)
	return true
}

func DoNextAction(shbr *clientapi.SendHeartbeatReply, cid int64, addr string) bool {
	var nCases = map[int]func(in1 interface{}, in2 interface{}, in3 interface{}) bool{
		0: ClearCommands,
		1: SendNewConf,
		2: GetNewTrurp,
		3: SendconfAndGetrep,
	}
	if nCases[int(shbr.GetNextAction())] == nil {
		return false
	}
	return nCases[int(shbr.GetNextAction())](shbr, cid, addr)
}
