package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

const testBiosManifest = `0 f797cb88c4b07745a129f35ea01b47c6c309cda9 08
0 dca68da0707a9a52b24db82def84f26fa463b44d 01
0 dd9efa31c88f467c3d21d3b28de4c53b8d55f3bc 01
0 dd261ca7511a7daf9e16cb572318e8e5fbd22963 01
0 df22cabc0e09aabf938bcb8ff76853dbcaae670d 01
0 a0d023a7f94efcdbc8bb95ab415d839bdfd73e9e 01
0 38dd128dc93ff91df1291a1c9008dcf251a0ef39 01
0 dd261ca7511a7daf9e16cb572318e8e5fbd22963 01
0 df22cabc0e09aabf938bcb8ff76853dbcaae670d 01
0 a0d023a7f94efcdbc8bb95ab415d839bdfd73e9e 01`

const testIMAManifest = `10 7971593a7ad22a7cce5b234e4bc5d71b04696af4 ima b5a166c10d153b7cc3e5b4f1eab1f71672b7c524 boot_aggregate
10 2c7020ad8cab6b7419e4973171cb704bdbf52f77 ima e09e048c48301268ff38645f4c006137e42951d0 /init
10 ef7a0aff83dd46603ebd13d1d789445365adb3b3 ima 0f8b3432535d5eab912ad3ba744507e35e3617c1 /init
10 247dba6fc82b346803660382d1973c019243e59f ima 747acb096b906392a62734916e0bb39cef540931 ld-2.9.so
10 341de30a46fa55976b26e55e0e19ad22b5712dcb ima 326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a ld.so.cache`

// TODO: Use test data for testing, including cert, client info, manifest. Wait for fixing.
func main() {
	const addr string = "127.0.0.1:40001"
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	cid := config.GetDefault().GetClientId()
	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	if cid <= 0 {
		ak, _, err := ractools.GetAk()
		if err != nil {
			log.Fatal("Client:can't Create EkCert")
		}
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
		if err != nil {
			log.Fatal("Client:client info marshal fail")
		}
		bk, err := clientapi.DoRegisterClient(addr, &clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: createRandomCert()},
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
		ractools.GetEkCert()
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
	// TODO: need real data
	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		log.Fatal("Client:client info marshal fail")
	}
	rIn, err := ractools.GetTrustReport(ractools.TrustReportIn{
		Nonce:      rpy.GetActionParameters().GetNonce(),
		ClientId:   id,
		ClientInfo: string(ci),
	})
	if err != nil {
		log.Fatalf("Client: create a new trust report failed :%v", err)
		return
	}

	// TODO: need real data
	srr, _ := clientapi.DoSendReport(srv, &clientapi.SendReportRequest{
		ClientId: id,
		TrustReport: &clientapi.TrustReport{
			ClientId: id,
			ClientInfo: &clientapi.ClientInfo{
				ClientInfo: rIn.ClientInfo,
			},
			PcrInfo: &clientapi.PcrInfo{
				Algorithm: "SHA1",
				PcrValues: map[int32]string{
					1: "pcr value1",
					2: "pcr value2",
				},
				PcrQuote: &clientapi.PcrQuote{
					Quoted: []byte("test quote"),
				},
			},
			Manifest: []*clientapi.Manifest{
				0: {
					Type: "bios",
					Item: []byte(testBiosManifest),
				},
				1: {
					Type: "ima",
					Item: []byte(testIMAManifest),
				},
			},
		},
	})
	if srr.Result {
		log.Printf("Client: send a new trust report to RAS ok.")
	} else {
		log.Printf("Client: send a new trust report to RAS failed.")
	}
}

func createRandomCert() []byte {
	str := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	strBytes := []byte(str)
	randomCert := []byte{}
	ra := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 6; i++ {
		randomCert = append(randomCert, strBytes[ra.Intn(len(strBytes))])
	}
	return randomCert
}
