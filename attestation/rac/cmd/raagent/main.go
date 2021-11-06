package main

import (
	"fmt"
	"log"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

const certPEM = `
-----BEGIN CERTIFICATE-----
MIIDujCCAqKgAwIBAgIIE31FZVaPXTUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMTI5MTMyNzQzWhcNMTQwNTI5MDAwMDAw
WjBpMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEYMBYGA1UEAwwPbWFp
bC5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfRrObuSW5T7q
5CnSEqefEmtH4CCv6+5EckuriNr1CjfVvqzwfAhopXkLrq45EQm8vkmf7W96XJhC
7ZM0dYi1/qOCAU8wggFLMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAa
BgNVHREEEzARgg9tYWlsLmdvb2dsZS5jb20wCwYDVR0PBAQDAgeAMGgGCCsGAQUF
BwEBBFwwWjArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcy
LmNydDArBggrBgEFBQcwAYYfaHR0cDovL2NsaWVudHMxLmdvb2dsZS5jb20vb2Nz
cDAdBgNVHQ4EFgQUiJxtimAuTfwb+aUtBn5UYKreKvMwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRK3QYWG7z2aLV29YG2u2IaulqBLzAXBgNVHSAEEDAOMAwGCisG
AQQB1nkCBQEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29t
L0dJQUcyLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAH6RYHxHdcGpMpFE3oxDoFnP+
gtuBCHan2yE2GRbJ2Cw8Lw0MmuKqHlf9RSeYfd3BXeKkj1qO6TVKwCh+0HdZk283
TZZyzmEOyclm3UGFYe82P/iDFt+CeQ3NpmBg+GoaVCuWAARJN/KfglbLyyYygcQq
0SgeDh8dRKUiaW3HQSoYvTvdTuqzwK4CXsr3b5/dAOY8uMuG/IAR3FgwTbZ1dtoW
RvOTa8hYiU6A475WuZKyEHcwnGYe57u2I2KbMgcKjPniocj4QzgYsVAVKW3IwaOh
yE+vPxsiUkvQHdO2fojCkY8jg70jxM+gu59tPDNbw3Uh/2Ij310FgTHsnGQMyA==
-----END CERTIFICATE-----`
const pubPEM = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`

func main() {
	const addr string = "127.0.0.1:40001"
	// step 1. get configuration from local file, clientId, hbDuration, Cert, etc.
	cid := config.GetDefaultRac().GetClientId()
	// step 2. if rac doesn't have clientId, it uses Cert to do the register process.
	if cid == -1 {
		ak, _, err := ractools.GetAk()

		req := clientapi.CreateIKCertRequest{
			EkCert: certPEM,
			IkPub:  pubPEM,
			IkName: ak.Name,
		}
		bkk, err := clientapi.DoCreateIKCert(addr, &req)
		if err != nil {
			log.Fatal("Client:can't Create IkCert")
		}
		eic := bkk.GetIcEncrypted()
		log.Println("Client:get encryptedIC=", eic)

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
		result := DoNextAction(bk, cid, addr)
		if result {
			log.Printf("do next action ok.")
		} else {
			log.Printf("do next action failed.")
		}
		// step 5. what else??

		// step n. sleep and wait.
		time.Sleep(config.GetDefaultRac().GetHBDuration())
	}
}

//具体的动作函数

func SendNewConf(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	fmt.Printf("send new configuration to RAC.")
	return true
}

func GetNewTstRep(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	fmt.Printf("get a new trust report from RAC.")
	_, err := ractools.GetTrustReport(ractools.TrustReportIn{
		ImaPath:    "",
		Nonce:      in1.(*clientapi.SendHeartbeatReply).GetActionParameters().GetNonce(),
		ClientId:   in2.(int64),
		ClientInfo: map[string]string{},
	})
	srr, _ := clientapi.DoSendReport(in3.(string), &clientapi.SendReportRequest{
		ClientId:    in2.(int64),
		TrustReport: nil,
	})
	if err != nil {
		log.Fatalf("create a new trust report failed :%v", err)
	} else {
		log.Printf("create a new trust report from RAC ok.")
	}
	if srr.Result {
		log.Printf("send a new trust report from RAC ok.")
	} else {
		log.Printf("send a new trust report from RAC failed.")
	}
	return true
}

func SendconfAndGetrep(in1 interface{}, in2 interface{}, in3 interface{}) bool {
	_ = SendNewConf(in1, in2, in3)
	_ = GetNewTstRep(in1, in2, in3)
	return true
}

func DoNextAction(shbr *clientapi.SendHeartbeatReply, cid int64, addr string) bool {
	var nCases = map[int]func(in1 interface{}, in2 interface{}, in3 interface{}) bool{
		1: SendNewConf,
		2: GetNewTstRep,
		3: SendconfAndGetrep,
	}
	if nCases[int(shbr.GetNextAction())] == nil {
		return false
	}
	return nCases[int(shbr.GetNextAction())](shbr, cid, addr)
}
