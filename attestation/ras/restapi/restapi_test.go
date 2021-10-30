package restapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
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

	server := NewRasServer()
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
