package restapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func CreateServer(t *testing.T) {
	router := echo.New()

	v, err := internal.NewFakeAuthenticator()
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

	v, err := internal.NewFakeAuthenticator()
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
	t.Log("restapi created server")
	go CreateServer(t)
	time.Sleep(time.Duration(5) * time.Second)
	t.Log("restapi created client")
	CreateClient(t)
}

func TestGetConfig(t *testing.T) {
	t.Log("Get config as follows:")
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
	var configJSON0 = `[{"name":"dbName", "value":"kpSecl"}, {"name":"dbPort", "value":"1234"}]`
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
	e := echo.New()
	req := httptest.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	vm, err := verifier.CreateVerifierMgr()
	require.NoError(t, err)
	cm := cache.CreateCacheMgr(100, vm)
	s := NewRasServer(cm)
	err = s.GetStatus(ctx)
	if assert.NoError(t, err) {
		assert.Equal(t, http.StatusOK, rec.Code)
		t.Log(rec.Body)
	}
}
