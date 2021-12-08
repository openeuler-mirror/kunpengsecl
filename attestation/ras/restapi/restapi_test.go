package restapi

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	resttest "gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testExtractor struct {
}

var (
	authKeyFile    = "./ecdsakey"
	authKeyPubFile = "./ecdsakey.pub"
)

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

func CreateServer(t *testing.T) {
	router := echo.New()

	v, err := internal.NewFakeAuthenticator(authKeyPubFile)
	require.NoError(t, err)

	av, err := CreateAuthValidator(v)
	require.NoError(t, err)

	router.Pre(middleware.RemoveTrailingSlash())
	router.Use(middleware.Logger())
	router.Use(av)

	vm, err := verifier.CreateVerifierMgr()
	require.NoError(t, err)

	cm := cache.CreateCacheMgr(100, vm)
	server := NewRasServer(cm)
	RegisterHandlers(router, server)

	router.Logger.Fatal(router.Start("127.0.0.1:5098"))
}

func AddAuthReqEditor(jws string) RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+jws)
		return nil
	}
}

func CreateClient(t *testing.T) {
	c, _ := NewClientWithResponses("http://127.0.0.1:5098")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v, err := internal.NewFakeAuthenticator(authKeyFile)
	require.NoError(t, err)

	// create a JWT with no scopes.
	emptyJWT, err := v.CreateJWSWithClaims([]string{})
	require.NoError(t, err)
	t.Logf("empty jwt: %s", string(emptyJWT))

	// create a JWT with write permission to config.
	writeJWT, err := v.CreateJWSWithClaims([]string{"write:config"})
	require.NoError(t, err)
	t.Logf("write jwt: %s", string(writeJWT))

	name := "version"
	value := "0.1.0"
	body := PostConfigJSONRequestBody{{&name, &value}}
	configResponse, err := c.GetConfigWithResponse(ctx)
	require.NoError(t, err)
	//	assert.Equal(t, http.StatusForbidden, configResponse.StatusCode())
	assert.Equal(t, http.StatusOK, configResponse.StatusCode())

	configResponse, err = c.GetConfigWithResponse(ctx, AddAuthReqEditor(string(emptyJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, configResponse.StatusCode())

	configResponse1, err := c.PostConfigWithResponse(ctx, body, AddAuthReqEditor(string(emptyJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, configResponse1.StatusCode())

	configResponse1, err = c.PostConfigWithResponse(ctx, body, AddAuthReqEditor(string(writeJWT)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, configResponse1.StatusCode())
}

func TestRestAPI(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	resttest.CreateAuthKeyFile(authKeyFile, authKeyPubFile)
	defer resttest.RemoveAuthKeyFile()

	t.Log("restapi created server")
	go CreateServer(t)
	time.Sleep(time.Duration(5) * time.Second)
	t.Log("restapi created client")
	CreateClient(t)
}

func TestGetConfig(t *testing.T) {
	t.Log("Get config as follows:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := NewRasServer(nil)
	err := s.GetConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

func TestPostConfig(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	var configJSON0 = `[{"name":"dbName", "value":"kunpengsecl"}, {"name":"dbPort", "value":"5432"}]`
	var configJSON1 = `[{"name":"port", "value":"1000"}]`
	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON0))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s := NewRasServer(nil)
	t.Log("The former config is: ")
	_ = s.GetConfig(ctx)
	t.Log(rec.Body)
	err := s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log("The modified config is: ")
		rec = httptest.NewRecorder()
		ctx = e.NewContext(req, rec)
		_ = s.GetConfig(ctx)
		t.Log(rec.Body)
	}
	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(configJSON1))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	ctx = e.NewContext(req, rec)
	err = s.PostConfig(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log("The current config is: ")
		rec = httptest.NewRecorder()
		ctx = e.NewContext(req, rec)
		_ = s.GetConfig(ctx)
		t.Log(rec.Body)
	}
}

func TestGetStatus(t *testing.T) {
	t.Log("Get Status:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s, cid := prepareServers(t)

	err := s.GetStatus(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(cid, rec.Body)
	}
}
func TestGetServer(t *testing.T) {
	t.Log("Get server:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, _ := prepareServers(t)
	err := s.GetServer(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}

}

func TestPutServer(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, _ := prepareServers(t)
	var serverJSON0 = `{"clientids":[1], "registered":false}`
	var serverJSON1 = `{"clientids":[1], "registered":true}`

	e := echo.New()
	req := httptest.NewRequest(echo.POST, "/", strings.NewReader(serverJSON0))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	err := s.PutServer(ctx)
	regClient, _ := trustmgr.GetRegisterClientById(1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Logf("Get the current server registered status as follows:%v", !regClient.IsDeleted)
	}

	req = httptest.NewRequest(echo.POST, "/", strings.NewReader(serverJSON1))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	err = s.PutServer(ctx)
	regClient, _ = trustmgr.GetRegisterClientById(1)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Logf("Get the current server registered status as follows:%v", !regClient.IsDeleted)
	}
}

func TestGetServerBasevalue(t *testing.T) {
	t.Log("Get Server Basevalue by server id:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	s, cid := prepareServers(t)
	err := s.GetServerBasevalueServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log((rec.Body))
	}
}

func TestPutServerBasevalue(t *testing.T) {
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	s, cid := prepareServers(t)
	var baseValueJSON = `{
		"algorithm":"SHA1", 
		"measurements":[{
			"name":"mName",
			"type":"mType",
			"value":"mValue"
		}], 
		"pcrvalues":[{
			"index":1, 
			"value":"pcr value1"
		}]
	}`

	e := echo.New()
	req := httptest.NewRequest(echo.PUT, "/", strings.NewReader(baseValueJSON))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	_ = s.GetServerBasevalueServerId(ctx, cid)
	t.Logf("Get former base value:%v", rec.Body)

	err := s.PutServerBasevalueServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		rec = httptest.NewRecorder()
		ctx = e.NewContext(req, rec)
		_ = s.GetServerBasevalueServerId(ctx, cid)
		t.Logf("Get current base value:%v", rec.Body)
	}
}

func TestGetReportServerId(t *testing.T) {
	t.Log("Get server report:")
	test.CreateServerConfigFile()
	config.GetDefault(config.ConfServer)
	defer test.RemoveConfigFile()

	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	s, cid := prepareServers(t)

	err := s.GetReportServerId(ctx, cid)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
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

func prepareServers(t *testing.T) (*RasServer, int64) {
	trustmgr.SetExtractor(&testExtractor{})
	vm, err := verifier.CreateVerifierMgr()
	require.NoError(t, err)
	cm := cache.CreateCacheMgr(cache.DEFAULTRACNUM, vm)
	s := NewRasServer(cm)
	sc := clientapi.NewServer(cm)

	ci, err := json.Marshal(map[string]string{"test name": "test value"})
	if err != nil {
		t.Error(err)
	}

	r, err := sc.RegisterClient(context.Background(),
		&clientapi.RegisterClientRequest{
			Ic:         &clientapi.Cert{Cert: createRandomCert()},
			ClientInfo: &clientapi.ClientInfo{ClientInfo: string(ci)},
		})
	if err != nil {
		t.Errorf("Client: invoke RegisterClient error %v", err)
	}
	t.Logf("Client: invoke RegisterClient ok, clientID=%d", r.GetClientId())
	cfg := config.GetDefault(config.ConfServer)
	trustmgr.SetValidator(&testValidator{})
	_, err = sc.SendReport(context.Background(),
		&clientapi.SendReportRequest{
			ClientId: r.GetClientId(),
			TrustReport: &clientapi.TrustReport{
				PcrInfo: &clientapi.PcrInfo{
					PcrValues: map[int32]string{
						1: "pcr value1",
						2: "pcr value2",
					},
					PcrQuote: &clientapi.PcrQuote{
						Quoted: []byte("test quote"),
					},
					Algorithm: cfg.GetDigestAlgorithm(),
				},
				Manifest: []*clientapi.Manifest{},
				ClientId: r.GetClientId(),
			}})
	if err != nil {
		t.Errorf("Client: invoke SendReport error %v", err)
	}
	t.Logf("Client: invoke SendReport ok")

	return s, r.GetClientId()
}
