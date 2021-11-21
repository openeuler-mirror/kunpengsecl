package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwt"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
)

type RasServer struct {
}

// Return a list of all config items in key:value pair format
// (GET /config)
func (s *RasServer) GetConfig(ctx echo.Context) error {
	cfg := config.GetDefault()
	er := cfg.GetExtractRules()
	jsonER, err := json.Marshal(er)
	if err != nil {
		fmt.Println(err)
	}
	strER := string(jsonER)
	cfgMap := map[string]string{
		"dbHost":        cfg.GetHost(),
		"dbName":        cfg.GetDBName(),
		"dbUser":        cfg.GetUser(),
		"dbPort":        fmt.Sprint(cfg.GetPort()),
		"mgrStrategy":   cfg.GetMgrStrategy(),
		"changeTime":    fmt.Sprint(cfg.GetChangeTime()),
		"extractRules":  strER,
		"hbDuration":    fmt.Sprint(cfg.GetHBDuration()),
		"trustDuration": fmt.Sprint(cfg.GetTrustDuration()),
	}
	configs := []ConfigItem{}
	for key, val := range cfgMap {
                k, v := key, val
		configs = append(configs, ConfigItem{&k, &v})
	}
	return ctx.JSON(http.StatusOK, configs)
}

// Create a list of config items
// (POST /config)
func (s *RasServer) PostConfig(ctx echo.Context) error {
	var configBody PostConfigJSONBody
	_ = ctx.Bind(&configBody)
	fmt.Println(configBody)
	return nil
}

// Return the trust report for the given server
// (GET /report/{serverId})
func (s *RasServer) GetReportServerId(ctx echo.Context, serverId int64) error {

	return ctx.JSON(http.StatusOK, nil)
}

// Return a list of briefing info for all servers
// (GET /server)
func (s *RasServer) GetServer(ctx echo.Context) error {

	return ctx.JSON(http.StatusOK, nil)
}

// put a list of servers into regitered status
// (PUT /server)
func (s *RasServer) PutServer(ctx echo.Context) error {

	return nil
}

// Return a list of trust status for all servers
// (GET /status)
func (s *RasServer) GetStatus(ctx echo.Context) error {

	return ctx.JSON(http.StatusOK, nil)
}

// Return the version of current API
// (GET /version)
func (s *RasServer) GetVersion(ctx echo.Context) error {

	return ctx.JSON(http.StatusOK, "0.1.0")
}

func NewRasServer() *RasServer {
	return &RasServer{}
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
					// check expected security scheme
					if in.SecuritySchemeName != "servermgt_auth" {
						return fmt.Errorf("security scheme %s != 'servermgt_auth'", in.SecuritySchemeName)
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

func StartServer(addr string) {
	router := echo.New()

	// FIXME: need to be replaced with a formal authenticator implementation
	v, err := internal.NewFakeAuthenticator()
	if err != nil {
		fmt.Println(err)
		return
	}

	av, err := CreateAuthValidator(v)
	if err != nil {
		fmt.Println(err)
		return
	}

	router.Pre(echomiddleware.RemoveTrailingSlash())
	router.Use(echomiddleware.Logger())
	router.Use(av)

	server := NewRasServer()
	RegisterHandlers(router, server)

	router.Logger.Fatal(router.Start(addr))
}
