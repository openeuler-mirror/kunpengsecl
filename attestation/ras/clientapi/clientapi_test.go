package clientapi

import (
	"context"
	"encoding/json"
	"math/rand"
	"os"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	grpc "google.golang.org/grpc"
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

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}
func TestClientAPI(t *testing.T) {
	const addr string = "127.0.0.1:40001"
	test.CreateConfigFile()
	defer func() {
		os.Remove("./config.yaml")
	}()
	go StartServer(addr)

	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Errorf("Client: fail to connect %v", err)
	}
	defer conn.Close()
	c := NewRasClient(conn)
	t.Logf("Client: connect to %s", addr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err = c.CreateIKCert(ctx, &CreateIKCertRequest{
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
