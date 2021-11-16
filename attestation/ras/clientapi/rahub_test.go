package clientapi

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRaHub(t *testing.T) {
	const addr string = "127.0.0.1:40004"
	createConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
	go StartServer(addr)

	const addrRaHub string = "127.0.0.1:40003"
	go StartRaHub(addrRaHub, addr)

	_, err := DoCreateIKCert(addrRaHub, &CreateIKCertRequest{
		EkCert: certPEM,
		IkPub:  pubPEM,
		IkName: nil,
	})
	if err != nil {
		t.Errorf("Client: invoke CreateIKCert error %v", err)
	}
	t.Logf("Client: invoke CreateIKCert ok")

	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		t.Error(err)
	}
	r, err := DoRegisterClient(addrRaHub, &RegisterClientRequest{
		Ic:         &Cert{Cert: []byte("register cert")},
		ClientInfo: &ClientInfo{ClientInfo: string(ci)},
	})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())

	_, err = DoSendHeartbeat(addrRaHub, &SendHeartbeatRequest{ClientId: 1})
	if err != nil {
		t.Errorf("Client: invoke SendHeartbeat error %v", err)
	}
	t.Logf("Client: invoke SendHeartbeat ok")

	_, err = DoSendReport(addrRaHub, &SendReportRequest{ClientId: 1})
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
