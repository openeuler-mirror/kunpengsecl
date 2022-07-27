package clientapi

import (
	context "context"
	rands "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
)

const (
	certPEM = `
-----BEGIN CERTIFICATE-----
MIIC+TCCAeGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA3MQ4wDAYDVQQGEwVDaGlu
YTEQMA4GA1UEChMHQ29tcGFueTETMBEGA1UEAxMKcHJpdmFjeSBjYTAeFw0yMTEx
MjUxODAxMDZaFw0zMTExMjUxODAxMTZaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCmT3Oxoot7afKoGIWRUl8BzschYIn1wMj+iOe4H9gFYMARUlFW
IkxzORQ1KcFGBsXOJhS+eMY27bJmT/N4pZdjmxMLdI+K0SmvR+BQ83kKVi548yDd
KnvGzPq7VHNqxuBhUTgKAwuakL74FToO2znrwPEBpIMF5a8KCAxD1bMeqqLfFtrL
aBAjCr602IqmAgETJBtL6yShu7UAavb+v/Bw/BPPURWGoY+ow71bRksgVcZUniW8
RzbbJqxE1/3igg5eDV1t6CPlm6mA8kYeRGIiN8E9NcSpiioaVaI9Jj5Cq6LSD3xV
h4HsXxCDfAxDdgPJMrd7ovII9m3D5iOWhDhJAgMBAAGjRzBFMA4GA1UdDwEB/wQE
AwICpDAfBgNVHSMEGDAWgBSX6ldIIk0hf/omuS9K6BEkFByPrDASBgNVHREBAf8E
CDAGhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQAgGxgJoZqG7wtaItCGO/TT90KH
Nau4VYB47KjyQhTJaKFZFlCnch7PcrJSec979c6peeEiL38vs1ss6sJfysMP5oHm
VaSsKcwSWu5AwdJgMtGjeLS9kYLIZ+dmsj9hqbsRfVFuWI8ZXjDKd7U0h9CIBxyf
5P/JseBTvSmcxPj59UzvBtM62y8Fp1cNB/jS5EHyRawrEdiIz0a+LFJjvI5wb7Hf
S4STUuqlIXl99dY9LQXa91BrgJBK8mmRz8TsrOm9SlIQ9Yo1q0jqZf2XLRzwQR5q
qc1NLPCFRTmZGhwf89f0/He0ZVu6lJxiImHrwf87wE0Vl0vJX30bToN1uTfh
-----END CERTIFICATE-----`
	pubPEM = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoAb/71DnejReEHw/+4uJ
9CmS2+ddGtiSrXx4hVsPDDQ2B+JPUmiu+jXMbP5V+nESHha+PUK9YcGnEbswG30S
PBYTQrS6OxMZPco00kQRQ5Vxr3DU6XgANNrPu5zJ90i3+Xrg68d8TzuxUtMGqhpa
PO5vqkiNjL3hImxVsS9NBwvr6Kpj+1lz+gbIeqaOBdVMO73jjZ6a/P1X8s3VnnON
OSXvLKEsN42HJeLVTORqgRWsAdBLePzU1H64HX9UrfyctddXyFXEK6lKYj6cX80F
C0GSKj5qlMUmiTG0PieeX/L2T4tQna+LB3tHVMmw/P14E92Zm9Cx7aImMfEExiOZ
3QIDAQAB
-----END PUBLIC KEY-----`
)

/*
var testBiosManifest = []byte{0x0, 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x25, 0x0, 0x0, 0x0, 0x53, 0x70, 0x65, 0x63, 0x20, 0x49, 0x44, 0x20, 0x45,
	0x76, 0x65, 0x6e, 0x74, 0x30, 0x33, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x2, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x14,
	0x0, 0xb, 0x0, 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x53, 0x93,
	0x3b, 0xe8, 0x90, 0x80, 0xc1, 0xfd, 0xc6, 0x35, 0x2b, 0xb6, 0xc8, 0xe7, 0x87, 0x99, 0xd0, 0x1f, 0x23, 0x0, 0xb,
	0x0, 0x77, 0xe4, 0x1e, 0x1a, 0x6e, 0x98, 0xf7, 0x16, 0xa, 0x8b, 0xa8, 0x5d, 0x1b, 0x68, 0x1d, 0xf8, 0x4b, 0x74,
	0x9f, 0x88, 0xff, 0xd5, 0x85, 0x61, 0x2e, 0x14, 0x54, 0x21, 0xb4, 0x2e, 0xe5, 0x81, 0xa, 0x0, 0x0, 0x0, 0x31,
	0x0, 0x2e, 0x0, 0x30, 0x0, 0x38, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x80, 0x2, 0x0, 0x0, 0x0,
	0x4, 0x0, 0xc6, 0xda, 0xaa, 0xf6, 0x6e, 0xfc, 0xe1, 0x2d, 0x87, 0x25, 0x4e, 0xb5, 0xdc, 0x4b, 0xd2, 0xb8,
	0xad, 0xd, 0xc0, 0x85, 0xb, 0x0, 0x72, 0x3e, 0xd4, 0xcf, 0x5a, 0xcc, 0xf6, 0x5d, 0x8f, 0xe6, 0x84, 0x49,
	0x1d, 0x5c, 0xb1, 0xf6, 0x16, 0x7f, 0x63, 0x15, 0xfa, 0x55, 0x3d, 0x57, 0xfb, 0xf9, 0x46, 0x66, 0x7b, 0x7,
	0xc2, 0xad, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10, 0x5f, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x38, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x80, 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, 0x2f, 0x20, 0x11, 0x2a, 0x3f,
	0x55, 0x39, 0x8b, 0x20, 0x8e, 0xc, 0x42, 0x68, 0x13, 0x89, 0xb4, 0xcb, 0x5b, 0x18, 0x23, 0xb, 0x0, 0xce,
	0x9c, 0xe3, 0x86, 0xb5, 0x2e, 0x9, 0x9f, 0x30, 0x19, 0xe5, 0x12, 0xa0, 0xd6, 0x6, 0x2d, 0x6b, 0x56, 0xe,
	0xfe, 0x4f, 0xf3, 0xe5, 0x66, 0x1c, 0x75, 0x25, 0xe2, 0xf9, 0xc2, 0x63, 0xdf, 0x34, 0x0, 0x0, 0x0, 0x61,
	0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0xd, 0x0, 0xe0, 0x98, 0x3, 0x2b, 0x8c, 0xa, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53, 0x0, 0x65, 0x0, 0x63, 0x0, 0x75, 0x0, 0x72,
	0x0, 0x65, 0x0, 0x42, 0x0, 0x6f, 0x0, 0x6f, 0x0, 0x74, 0x0}

const testIMAManifest = `10 7971593a7ad22a7cce5b234e4bc5d71b04696af4 ima b5a166c10d153b7cc3e5b4f1eab1f71672b7c524 boot_aggregate
10 2c7020ad8cab6b7419e4973171cb704bdbf52f77 ima e09e048c48301268ff38645f4c006137e42951d0 /init
10 ef7a0aff83dd46603ebd13d1d789445365adb3b3 ima 0f8b3432535d5eab912ad3ba744507e35e3617c1 /init
10 247dba6fc82b346803660382d1973c019243e59f ima 747acb096b906392a62734916e0bb39cef540931 ld-2.9.so
10 341de30a46fa55976b26e55e0e19ad22b5712dcb ima 326045fc3d74d8c8b23ac8ec0a4d03fdacd9618a ld.so.cache`
*/
const serverConfig = `
database:
  host: localhost
  name: kunpengsecl
  password: postgres
  port: 5432
  user: postgres
log:
  file: ./logs/ras-log.txt
racconfig:
  digestalgorithm: sha1
  hbduration: 10s
  trustduration: 2m0s
rasconfig:
  authkeyfile: ./ecdsakey.pub
  pcakeycertfile: ""
  pcaprivkeyfile: ""
  restport: 127.0.0.1:40002
  rootkeycertfile: ""
  rootprivkeyfile: ""
  serialnumber: 0
  serverport: 127.0.0.1:40001
  onlineduration: 30s
  basevalue-extract-rules:
    manifest:
    - name:
      - 8-0
      - 80000008-1
      type: bios
    - name:
      - boot_aggregate
      - /etc/modprobe.d/tuned.conf
      type: ima
    pcrinfo:
      pcrselection:
      - 1
      - 2
      - 3
      - 4
`

const (
	configFilePath = "./config.yaml"
)

var (
	testIKName = []byte{0, 11, 130, 124, 52, 60, 98, 255, 198, 119, 239, 45, 169, 164, 218,
		151, 236, 96, 199, 100, 68, 45, 135, 69, 40, 229, 173, 119, 148, 163, 197, 35, 62, 159}
	emptyClientInfoErr  = "create empty ClientInfo error"
	createClientInfoErr = "create test ClientInfo error"
	testClientInfo      = map[string]string{"test name": "test value"}
)

func CreateServerConfigFile() {
	ioutil.WriteFile(configFilePath, []byte(serverConfig), 0644)
}

func RemoveConfigFile() {
	os.Remove(configFilePath)
}

func TestClientapi(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()

	config.InitFlags()
	config.LoadConfigs()
	defer RemoveFiles()
	config.HandleFlags()
	server := config.GetServerPort()

	go StartServer(server)
	defer StopServer()

	ras, err := CreateConn(server)
	if err != nil {
		t.Errorf("fail to Create connection %v", err)
	}
	defer ReleaseConn(ras)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pubkeyBlock, _ := pem.Decode([]byte(pubPEM))
	reqEC := GenerateEKCertRequest{
		EkPub: pubkeyBlock.Bytes,
	}
	rspEC, err := ras.c.GenerateEKCert(ctx, &reqEC)
	if err != nil {
		t.Errorf("test GenerateEKCert error %v", err)
	}
	_, err = ras.c.GenerateIKCert(ctx, &GenerateIKCertRequest{
		EkCert: rspEC.EkCert,
		IkPub:  pubkeyBlock.Bytes,
		IkName: testIKName,
	})
	if err != nil {
		t.Errorf("test GenerateIKCert error %v", err)
	}

	// test empty clientinfo
	ci, err := json.Marshal(map[string]string{})
	if err != nil {
		t.Error(emptyClientInfoErr)
	}
	r, err := ras.c.RegisterClient(ctx, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test RegisterClient with empty clientinfo error %v", err)
	}
	_, err = ras.c.UnregisterClient(ctx, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test UnregisterClient with empty clientinfo error %v", err)
	}

	// test empty request
	_, err = ras.c.RegisterClient(ctx, &RegisterClientRequest{})
	if err == nil {
		t.Errorf("test RegisterClient with empty request failed")
	}

	ci, err = json.Marshal(testClientInfo)
	if err != nil {
		t.Error(createClientInfoErr)
	}
	r, err = ras.c.RegisterClient(ctx, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test RegisterClient error %v", err)
	}

	// test empty clientId
	_, err = ras.c.SendHeartbeat(ctx, &SendHeartbeatRequest{})
	if err == nil {
		t.Errorf("test SendHeartbeat with empty ClientId failed")
	}

	_, err = ras.c.SendHeartbeat(ctx, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("test SendHeartbeat error %v", err)
	}

	// test empty report
	srRep, _ := ras.c.SendReport(ctx, &SendReportRequest{})
	if srRep.GetResult() {
		t.Errorf("test SendReport with empty report failed")
	}
	/*
		_, err = ras.c.SendReport(ctx, &SendReportRequest{
			ClientId:   r.GetClientId(),
			Nonce:      r.GetClientConfig().GetNonce(),
			ClientInfo: string(ci),
			Quoted:     []byte("test quote"),
			Signature:  []byte("test signature"),
			Manifests: []*Manifest{
				0: {Key: "pcr", Value: []byte("test pcr")},
				1: {Key: "bios", Value: testBiosManifest},
				2: {Key: "ima", Value: []byte(testIMAManifest)},
			},
		})
		if err != nil {
			t.Errorf("Client: invoke SendReport error %v", err)
		}
	*/

	// test empty clientId
	_, err = ras.c.UnregisterClient(ctx, &UnregisterClientRequest{})
	if err != nil {
		t.Errorf("test UnregisterClient with empty clientId failed %v", err)
	}

	_, err = ras.c.UnregisterClient(ctx, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test UnregisterClient error %v", err)
	}
}

func TestDoClientapi(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()

	config.LoadConfigs()
	defer RemoveFiles()
	config.HandleFlags()
	server := config.GetServerPort()
	/*vm, err := verifier.CreateVerifierMgr()
	if err != nil {
		fmt.Println(err)
		return
	}*/
	go StartServer(server)
	defer StopServer()

	pubkeyBlock, _ := pem.Decode([]byte(pubPEM))
	reqEC := GenerateEKCertRequest{
		EkPub: pubkeyBlock.Bytes,
	}
	rspEC, err := DoGenerateEKCert(server, &reqEC)
	if err != nil {
		t.Errorf("test DoGenerateEKCert error %v", err)
	}
	_, err = DoGenerateIKCert(server, &GenerateIKCertRequest{
		EkCert: rspEC.EkCert,
		IkPub:  pubkeyBlock.Bytes,
		IkName: testIKName,
	})
	if err != nil {
		t.Errorf("test DoGenerateIKCert error %v", err)
	}

	// test empty clientinfo
	ci, err := json.Marshal(map[string]string{})
	if err != nil {
		t.Error(emptyClientInfoErr)
	}
	r, err := DoRegisterClient(server, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test DoRegisterClient with empty clientinfo error %v", err)
	}
	_, err = DoUnregisterClient(server, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test DoUnregisterClient with empty clientinfo error %v", err)
	}

	// test empty request
	_, err = DoRegisterClient(server, &RegisterClientRequest{})
	if err == nil {
		t.Errorf("test DoRegisterClient with empty request failed")
	}

	ci, err = json.Marshal(testClientInfo)
	if err != nil {
		t.Error(createClientInfoErr)
	}
	r, err = DoRegisterClient(server, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test DoRegisterClient error %v", err)
	}

	// test empty clientId
	_, err = DoSendHeartbeat(server, &SendHeartbeatRequest{})
	if err == nil {
		t.Errorf("test DoSendHeartbeat with empty ClientId failed")
	}

	_, err = DoSendHeartbeat(server, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("test DoSendHeartbeat error %v", err)
	}

	// test empty report
	srRep, _ := DoSendReport(server, &SendReportRequest{})
	if srRep.GetResult() {
		t.Errorf("test DoSendReport with empty report failed")
	}
	/*
		_, err = DoSendReport(server, &SendReportRequest{
			ClientId:   r.GetClientId(),
			Nonce:      r.GetClientConfig().GetNonce(),
			ClientInfo: string(ci),
			Quoted:     []byte("test quote"),
			Signature:  []byte("test signature"),
			Manifests: []*Manifest{
				0: {Key: "pcr", Value: []byte("test pcr")},
				1: {Key: "bios", Value: testBiosManifest},
				2: {Key: "ima", Value: []byte(testIMAManifest)},
			},
		})
		if err != nil {
			t.Errorf("Client: invoke DoSendReport error %v", err)
		}
	*/

	// test empty clientId
	_, err = DoUnregisterClient(server, &UnregisterClientRequest{})
	if err != nil {
		t.Errorf("test DoUnregisterClient with empty clientId failed %v", err)
	}

	_, err = DoUnregisterClient(server, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test DoUnregisterClient error %v", err)
	}
}

func TestDoClientapiWithConn(t *testing.T) {
	CreateServerConfigFile()
	defer RemoveConfigFile()

	config.LoadConfigs()
	defer RemoveFiles()
	config.HandleFlags()
	server := config.GetServerPort()
	/*vm, err := verifier.CreateVerifierMgr()
	if err != nil {
		fmt.Println(err)
		return
	}*/
	go StartServer(server)
	defer StopServer()

	ras, err := CreateConn(server)
	if err != nil {
		t.Errorf("fail to Create connection %v", err)
	}
	defer ReleaseConn(ras)

	pubkeyBlock, _ := pem.Decode([]byte(pubPEM))
	reqEC := GenerateEKCertRequest{
		EkPub: pubkeyBlock.Bytes,
	}
	rspEC, err := DoGenerateEKCertWithConn(ras, &reqEC)
	if err != nil {
		t.Errorf("test DoGenerateEKCertWithConn error %v", err)
	}
	_, err = DoGenerateIKCertWithConn(ras, &GenerateIKCertRequest{
		EkCert: rspEC.EkCert,
		IkPub:  pubkeyBlock.Bytes,
		IkName: testIKName,
	})
	if err != nil {
		t.Errorf("test DoGenerateIKCertWithConn error %v", err)
	}

	// test empty clientinfo
	ci, err := json.Marshal(map[string]string{})
	if err != nil {
		t.Error(emptyClientInfoErr)
	}
	r, err := DoRegisterClientWithConn(ras, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test DoRegisterClientWithConn with empty clientinfo error %v", err)
	}
	_, err = DoUnregisterClientWithConn(ras, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test DoUnregisterClientWithConn with empty clientinfo error %v", err)
	}

	// test empty request
	_, err = DoRegisterClientWithConn(ras, &RegisterClientRequest{})
	if err == nil {
		t.Errorf("test DoRegisterClientWithConn with empty request failed")
	}

	ci, err = json.Marshal(testClientInfo)
	if err != nil {
		t.Error(createClientInfoErr)
	}
	r, err = DoRegisterClientWithConn(ras, &RegisterClientRequest{
		Cert:       createCert(),
		ClientInfo: string(ci),
	})
	if err != nil {
		t.Errorf("test DoRegisterClientWithConn error %v", err)
	}
	_, err = DoSendHeartbeatWithConn(ras, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("test DoSendHeartbeatWithConn error %v", err)
	}

	// test empty clientId
	_, err = DoSendHeartbeatWithConn(ras, &SendHeartbeatRequest{})
	if err == nil {
		t.Errorf("test SendHeartbeatWithConn with empty ClientId failed")
	}

	_, err = DoSendHeartbeatWithConn(ras, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("test SendHeartbeatWithConn error %v", err)
	}

	// test empty report
	srRep, _ := DoSendReportWithConn(ras, &SendReportRequest{})
	if srRep.GetResult() {
		t.Errorf("test DoSendReportWithConn with empty report failed")
	}
	/*
		srRep, _ = ras.c.SendReport(ctx, &SendReportRequest{
			ClientId:   r.GetClientId(),
			Nonce:      hbReply.ClientConfig.Nonce,
			ClientInfo: string(ci),
			Quoted:     []byte("test quote"),
			Signature:  []byte("test signature"),
			Manifests: []*Manifest{
				0: {Key: "pcr", Value: []byte(testPcrManifest)},
				1: {Key: "bios", Value: testBiosManifest},
				2: {Key: "ima", Value: []byte(testIMAManifest)},
			},
		})
		if srRep.Result != true {
			t.Errorf("test SendReport failed")
		}
	*/

	// test empty clientId
	_, err = DoUnregisterClientWithConn(ras, &UnregisterClientRequest{})
	if err != nil {
		t.Errorf("test DoUnregisterClientWithConn with empty clientId failed %v", err)
	}

	_, err = DoUnregisterClientWithConn(ras, &UnregisterClientRequest{
		ClientId: r.GetClientId(),
	})
	if err != nil {
		t.Errorf("test DoUnregisterClientWithConn error %v", err)
	}
}

func createCert() []byte {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rands.Int(rands.Reader, max)
	subject := pkix.Name{
		Organization: []string{"Company"},
		Country:      []string{"China"},
		CommonName:   "test ekcert",
	}

	Template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	key, _ := rsa.GenerateKey(rands.Reader, 2048)
	cert, _ := x509.CreateCertificate(rands.Reader, &Template, &Template, &key.PublicKey, key)
	return cert
}

func RemoveFiles() {
	os.Remove("./pca-root.crt")
	os.Remove("./pca-root.key")
	os.Remove("./pca-ek.crt")
	os.Remove("./pca-ek.key")
	os.Remove("./https.crt")
	os.Remove("./https.key")
}
