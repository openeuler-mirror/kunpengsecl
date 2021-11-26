package clientapi

import (
	"context"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"google.golang.org/grpc"
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

var testIKName = []byte{0, 11, 130, 124, 52, 60, 98, 255, 198, 119, 239, 45, 169, 164, 218,
	151, 236, 96, 199, 100, 68, 45, 135, 69, 40, 229, 173, 119, 148, 163, 197, 35, 62, 159}

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}

func TestClientAPI(t *testing.T) {
	test.CreateServerConfigFile()
	cfg := config.GetDefault()
	server := cfg.GetPort()
	defer test.RemoveConfigFile()
	go StartServer(server)

	conn, err := grpc.Dial(server, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Errorf("Client: fail to connect %v", err)
	}
	defer conn.Close()
	c := NewRasClient(conn)
	t.Logf("Client: connect to %s", server)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err = c.CreateIKCert(ctx, &CreateIKCertRequest{
		EkCert: certPEM,
		IkPub:  pubPEM,
		IkName: testIKName,
	})
	if err != nil {
		t.Errorf("Client: invoke CreateIKCert error %v", err)
	}
	t.Logf("Client: invoke CreateIKCert ok")

	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		t.Error(err)
	}
	r, err := c.RegisterClient(ctx, &RegisterClientRequest{
		Ic:         &Cert{Cert: createRandomCert()},
		ClientInfo: &ClientInfo{ClientInfo: string(ci)},
	})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())

	_, err = c.SendHeartbeat(ctx, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("Client: invoke SendHeartbeat error %v", err)
	}
	t.Logf("Client: invoke SendHeartbeat ok")

	trustmgr.SetValidator(&testValidator{})
	_, err = c.SendReport(ctx, &SendReportRequest{ClientId: r.GetClientId(), TrustReport: &TrustReport{
		PcrInfo: &PcrInfo{PcrValues: map[int32]string{
			1: "pcr value1",
			2: "pcr value2",
		},
			PcrQuote: &PcrQuote{
				Quoted: []byte("test quote"),
			},
			Algorithm: "SHA1",
		},
		Manifest: []*Manifest{
			0: {
				Type: "bios",
				Item: []byte(testBiosManifest),
			},
			1: {
				Type: "ima",
				Item: []byte(testIMAManifest),
			},
		},
		ClientId: r.GetClientId(),
	}})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")

	u, err := c.UnregisterClient(ctx,
		&UnregisterClientRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("Client: invoke UnregisterClient error %v", err)
	}
	t.Logf("Client: invoke UnregisterClient %v", u.GetResult())

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
