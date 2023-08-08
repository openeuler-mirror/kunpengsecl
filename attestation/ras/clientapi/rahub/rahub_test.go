/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3
Create: 2021-11-16
Description: Using leverage clientapi to implement a hub.
*/

package rahub

/*
import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
)

func TestRaHub(t *testing.T) {
	test.CreateServerConfigFile()
	// We can't use this default config, because the go test
	// will run TestRaHub and TestClientAPI parallelly, so
	// it can't bind the same port on the same host.
	// Here we just use another port to bind.
	//cfg := config.GetDefault()
	//server := cfg.GetPort()
	server := ":40004"
	defer test.RemoveConfigFile()
	vm, err := verifier.CreateVerifierMgr()
	if err != nil {
		fmt.Println(err)
		return
	}
	cm := cache.CreateCacheMgr(cache.DEFAULTRACNUM, vm)
	go StartServer(server, cm)

	const addrRaHub string = ":40003"
	go StartRaHub(addrRaHub, server)

	pubkeyBlock, _ := pem.Decode([]byte(pubPEM))
	_, err = DoGenerateEKCert(addrRaHub, &GenerateEKCertRequest{
		EkPub: pubkeyBlock.Bytes,
	})
	if err != nil {
		t.Errorf("Client: invoke GenerateEKCert error %v", err)
	}
	t.Logf("Client: invoke GenerateEKCert ok")

	certBlock, _ := pem.Decode([]byte(certPEM))
	ikpubBlock, _ := pem.Decode([]byte(pubPEM))
	_, err = DoGenerateIKCert(addrRaHub, &GenerateIKCertRequest{
		EkCert: certBlock.Bytes,
		IkPub:  ikpubBlock.Bytes,
		IkName: testIKName,
	})
	if err != nil {
		t.Errorf("Client: invoke GenerateIKCert error %v", err)
	}
	t.Logf("Client: invoke GenerateIKCert ok")

	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		t.Error(err)
	}
	r, err := DoRegisterClient(addrRaHub, &RegisterClientRequest{
		Ic:         &Cert{Cert: createRandomCert()},
		ClientInfo: &ClientInfo{ClientInfo: string(ci)},
	})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())

	_, err = DoSendHeartbeat(addrRaHub, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("Client: invoke SendHeartbeat error %v", err)
	}
	t.Logf("Client: invoke SendHeartbeat ok")

	cfg := config.GetDefault(config.ConfServer)
	trustmgr.SetValidator(&testValidator{})
	_, err = DoSendReport(addrRaHub, &SendReportRequest{ClientId: r.GetClientId(),
		TrustReport: &TrustReport{
			PcrInfo: &PcrInfo{PcrValues: map[int32]string{
				1: "pcr value1",
				2: "pcr value2",
			},
				PcrQuote: &PcrQuote{
					Quoted: []byte("test quote"),
				},
				Algorithm: cfg.GetDigestAlgorithm(),
			},
			Manifest: []*Manifest{},
			ClientId: r.GetClientId(),
		}})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")

	u, err := DoUnregisterClient(addrRaHub,
		&UnregisterClientRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("Client: invoke UnregisterClient error %v", err)
	}
	t.Logf("Client: invoke UnregisterClient %v", u.Result)

}
*/
