package clientapi

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
	"github.com/stretchr/testify/assert"
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

var testIKName = []byte{0, 11, 130, 124, 52, 60, 98, 255, 198, 119, 239, 45, 169, 164, 218,
	151, 236, 96, 199, 100, 68, 45, 135, 69, 40, 229, 173, 119, 148, 163, 197, 35, 62, 159}

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}

type testExtractor struct {
}

func (tv *testExtractor) Extract(report *entity.Report, mInfo *entity.MeasurementInfo) error {
	mInfo.ClientID = report.ClientID
	mInfo.PcrInfo = report.PcrInfo
	for _, mf := range report.Manifest {
		for _, mi := range mf.Items {
			mInfo.Manifest = append(mInfo.Manifest, entity.Measurement{
				Type:  mf.Type,
				Name:  mi.Name,
				Value: mi.Value,
			})
		}
	}
	return nil
}

func TestClientAPI(t *testing.T) {
	test.CreateServerConfigFile()
	cfg := config.GetDefault(config.ConfServer)
	server := cfg.GetPort()
	defer test.RemoveConfigFile()

	vm, err := verifier.CreateVerifierMgr()
	if err != nil {
		fmt.Println(err)
		return
	}
	cm := cache.CreateCacheMgr(cache.DEFAULTRACNUM, vm)
	go StartServer(server, cm)

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
	// test empty clientInfo
	_, err = c.RegisterClient(ctx, &RegisterClientRequest{
		Ic: &Cert{Cert: createRandomCert()},
	})
	assert.Error(t, err)
	// test empty request
	_, err = c.RegisterClient(ctx, &RegisterClientRequest{})
	assert.Error(t, err)
	r, err := c.RegisterClient(ctx, &RegisterClientRequest{
		Ic:         &Cert{Cert: createRandomCert()},
		ClientInfo: &ClientInfo{ClientInfo: string(ci)},
	})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())

	// test empty clientId
	hbReply, err := c.SendHeartbeat(ctx, &SendHeartbeatRequest{})
	if err != nil {
		t.Errorf("empty clientId test failed")
	}
	assert.Equal(t, uint64(0), hbReply.NextAction)
	_, err = c.SendHeartbeat(ctx, &SendHeartbeatRequest{ClientId: r.GetClientId()})
	if err != nil {
		t.Errorf("Client: invoke SendHeartbeat error %v", err)
	}
	t.Logf("Client: invoke SendHeartbeat ok")

	trustmgr.SetValidator(&testValidator{})
	ex := new(testExtractor)
	trustmgr.SetExtractor(ex)
	// test empty report
	srRep, err := c.SendReport(ctx, &SendReportRequest{})
	assert.Equal(t, false, srRep.GetResult())
	assert.Error(t, err)
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
		Manifest: []*Manifest{},
		ClientId: r.GetClientId(),
	}})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")
	// test empty clientId
	ucRep, err := c.UnregisterClient(ctx, &UnregisterClientRequest{})
	assert.Equal(t, false, ucRep.GetResult())
	assert.Error(t, err)
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

func TestUnMarshalBIOS(t *testing.T) {
	result, err := unmarshalBIOSManifest(testBiosManifest)
	if err != nil {
		t.Fatal("parse fail")
	}
	count := len(result.Items)
	if result.Items[count-1].Name != "2147483649-2" {
		t.Fatal("parse fail")
	}
}
