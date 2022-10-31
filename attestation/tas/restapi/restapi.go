/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-06-14
Description: provide rest api to outside to control tas server.

The following comments are just for test and make the rest api understand easily.

curl -X GET -H "Content-type: application/json" http://localhost:40009/config
curl -X POST -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40009/config

GET/POST /config        对TAS进行运行时配置的入口
*/

// restapi package provides the restful api interface based on openapi standard.
package restapi

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/restapi/internal"
	"github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	strNULL     = ``
	errNoClient = `rest api error: %v`
)

var (
	srv *echo.Echo = nil
)

type MyRestAPIServer struct {
}

func StartServer(addr string) {
	if srv != nil {
		return
	}
	srv = echo.New()
	v, err := internal.NewFakeAuthenticator(config.GetAuthKeyFile())
	if err != nil {
		fmt.Println(err)
		return
	}
	av, err := CreateAuthValidator(v)
	if err != nil {
		fmt.Println(err)
		return
	}
	srv.Use(av)
	RegisterHandlers(srv, &MyRestAPIServer{})
	log.Debug(srv.Start(addr))
}

func CreateTestAuthToken() ([]byte, error) {
	authKeyPubFile := config.GetAuthKeyFile()
	authKeyFile := os.TempDir() + "/at" + strconv.FormatInt(rand.Int63(), 16)
	test.CreateAuthKeyFile(authKeyFile, authKeyPubFile)
	defer os.Remove(authKeyFile)

	v, err := internal.NewFakeAuthenticator(authKeyFile)
	if err != nil {
		log.Errorf("Create Authenticator failed")
		return nil, err
	}

	// create a JWT with config write & server write permission
	writeJWT, err := v.CreateJWSWithClaims([]string{"write:config", "write:servers"})
	if err != nil {
		log.Errorf("Create Token failed")
		return nil, err
	}

	return writeJWT, nil
}

// getJWS fetch the JWS string from an Authorization header
func getJWS(req *http.Request) (string, error) {
	h := req.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("missing authorization header")
	}
	if !strings.HasPrefix(h, "Bearer ") {
		return "", fmt.Errorf("wrong authorization header content")
	}
	return strings.TrimPrefix(h, "Bearer "), nil
}

func checkScopes(expectedScopes []string, t jwt.Token) error {
	cls, err := getScopes(t)
	if err != nil {
		return fmt.Errorf("getting scopes: %w", err)
	}
	// Put the claims into a map, for quick access.
	clsm := map[string]byte{}
	for i := range cls {
		clsm[cls[i]] = 1
	}

	for i := range expectedScopes {
		if clsm[expectedScopes[i]] == 0 {
			return fmt.Errorf("invalide scopes")
		}
	}
	return nil
}

const (
	scopesClaim = "perm"
)

// getScopes returns a list of scopes from a JWT token.
func getScopes(t jwt.Token) ([]string, error) {
	raw, got := t.Get(scopesClaim)
	if !got {
		return []string{}, nil
	}

	// convert untyped JSON list to a string list.
	rawList, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' claim is not a list", scopesClaim)
	}

	cls := []string{}

	for i := range rawList {
		c, ok := rawList[i].(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] isn't a valid string", scopesClaim, i)
		}
		cls = append(cls, c)
	}
	return cls, nil
}

// JWSValidator is used to validate JWS payloads and return a JWT if they're
// valid
type JWSValidator interface {
	ValidateJWS(jws string) (jwt.Token, error)
}

func CreateAuthValidator(v JWSValidator) (echo.MiddlewareFunc, error) {
	spec, err := GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}

	validator := middleware.OapiRequestValidatorWithOptions(spec,
		&middleware.Options{
			Options: openapi3filter.Options{
				AuthenticationFunc: func(ctx context.Context, in *openapi3filter.AuthenticationInput) error {
					// ignore the not used template paramenter
					_ = ctx
					// check expected security scheme
					if in.SecuritySchemeName != "servermgt_oauth2" {
						return fmt.Errorf("security scheme %s != 'servermgt_oauth2'", in.SecuritySchemeName)
					}

					// get JWS from the request
					jws, err := getJWS(in.RequestValidationInput.Request)
					if err != nil {
						return fmt.Errorf("retrieving jws: %w", err)
					}

					// validate JWS and get JWT
					t, err := v.ValidateJWS(jws)
					if err != nil {
						return fmt.Errorf("checking JWS: %w", err)
					}

					// check scopes against the token
					err = checkScopes(in.Scopes, t)

					if err != nil {
						return fmt.Errorf("checking jwt token: %w", err)
					}
					return nil
				},
			},
		})

	return validator, nil
}

func checkJSON(ctx echo.Context) bool {
	cty := ctx.Request().Header.Get(echo.HeaderContentType)
	if cty == echo.MIMEApplicationJSON || cty == echo.MIMEApplicationJSONCharsetUTF8 {
		return true
	}
	return false
}

type cfgRecord struct {
	BaseValue string `json:"basevalue"`
}

func genConfigJSON() *cfgRecord {
	return &cfgRecord{
		BaseValue: config.GetBaseValue(),
	}
}

// (GET /config)
// get tas server configuration
//  read config as json
//    curl -X GET -H "Content-Type: application/json" http://localhost:40009/config
func (s *MyRestAPIServer) GetConfig(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJSON())
	}
	return fmt.Errorf("content type not support yet")
}

// (POST /config)
// modify tas server configuration
//  write config as json
//    curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -d '{"basevalue":"testvalue"}' http://localhost:40009/config
// Notice: key name must be enclosed by "" in json format!!!
func (s *MyRestAPIServer) PostConfig(ctx echo.Context) error {
	cfg := new(cfgRecord)
	err := ctx.Bind(cfg)
	if err != nil {
		log.Debugf(errNoClient, err)
		return err
	}
	if cfg.BaseValue != strNULL {
		config.SetBaseValue(cfg.BaseValue)
	}
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJSON())
	}
	return fmt.Errorf("content type not support yet")
}
