package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwt"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

type RasServer struct {
	cm *cache.CacheMgr
}

// Return a list of all config items in key:value pair format
// (GET /config)
func (s *RasServer) GetConfig(ctx echo.Context) error {
	cfg := config.GetDefault(config.ConfServer)
	er := cfg.GetExtractRules()
	jsonER, err := json.Marshal(er)
	if err != nil {
		fmt.Println(err)
	}
	strER := string(jsonER)
	cfgMap := map[string]string{
		"dbHost":          cfg.GetHost(),
		"dbName":          cfg.GetDBName(),
		"dbUser":          cfg.GetUser(),
		"dbPort":          fmt.Sprint(cfg.GetDBPort()),
		"mgrStrategy":     cfg.GetMgrStrategy(),
		"changeTime":      fmt.Sprint(cfg.GetChangeTime()),
		"extractRules":    strER,
		"hbDuration":      fmt.Sprint(cfg.GetHBDuration()),
		"trustDuration":   fmt.Sprint(cfg.GetTrustDuration()),
		"digestAlgorithm": cfg.GetDigestAlgorithm(),
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
	cfg := config.GetDefault(config.ConfServer)
	err := ctx.Bind(&configBody)
	if err != nil {
		fmt.Print("Bind configBody failed.")
		return err
	}
	fmt.Println(configBody)
	postCfgMap := map[string]func(s string){
		"dbHost":          func(s string) { cfg.SetHost(s) },
		"dbName":          func(s string) { cfg.SetDBName(s) },
		"dbUser":          func(s string) { cfg.SetUser(s) },
		"dbPort":          func(s string) { setDBport(s) },
		"dbPassword":      func(s string) { cfg.SetPassword(s) },
		"mgrStrategy":     func(s string) { cfg.SetMgrStrategy(s) },
		"extractRules":    func(s string) { setExtractRules(s) },
		"hbDuration":      func(s string) { setHBDuration(s) },
		"trustDuration":   func(s string) { setTDuration(s) },
		"digestAlgorithm": func(s string) { cfg.SetDigestAlgorithm(s) },
	}
	if len(configBody) == 0 {
		fmt.Print("Not have specification about the config items that need modified.\n")
		return nil
	}
	for i := range configBody {
		doFunc, ok := postCfgMap[*configBody[i].Name]
		if ok {
			doFunc(*configBody[i].Value)
		} else {
			fmt.Print("Modify config failed.\n")
		}
	}
	return nil
}

//Modify some config information respectively
func setDBport(val string) error {
	cfg := config.GetDefault(config.ConfServer)
	port, err := strconv.Atoi(val)
	if err != nil {
		fmt.Print("Convert string to int failed.")
		return err
	}
	cfg.SetDBPort(port)
	return nil
}

func setExtractRules(val string) error {
	cfg := config.GetDefault(config.ConfServer)
	jsonER := []byte(val)
	var extractRules entity.ExtractRules
	err := json.Unmarshal(jsonER, &extractRules)
	if err != nil {
		fmt.Print("Unmarshal byte to struct failed.")
		return err
	}
	cfg.SetExtractRules(extractRules)
	return nil
}

func setHBDuration(val string) error {
	cfg := config.GetDefault(config.ConfServer)
	duration, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		fmt.Print("Convert string to int64 failed.")
		return err
	}
	cfg.SetHBDuration(time.Duration(duration))
	return nil
}

func setTDuration(val string) error {
	cfg := config.GetDefault(config.ConfServer)
	duration, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		fmt.Print("Convert string to int64 failed.")
		return err
	}
	cfg.SetTrustDuration(time.Duration(duration))
	return nil
}

// Return the base value of a given container
// (GET /container/basevalue/{uuid})
func (s *RasServer) GetContainerBasevalueUuid(ctx echo.Context, uuid string) error {
	cbv, err := trustmgr.GetContainerBaseValueByUUId(uuid)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, nil)
	}
	return ctx.JSON(http.StatusOK, cbv)
}

// create/update the base value of the given container
// (PUT /container/basevalue/{uuid})
func (s *RasServer) PutContainerBasevalueUuid(ctx echo.Context, uuid string) error {
	var body PutContainerBasevalueUuidJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	cbv := map[string]string{}
	for _, m := range *body.Measurements {
		cbv[*m.Name] = *m.Value
	}
	trustmgr.AddContainerBaseValue(&entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         cbv,
	})
	return ctx.JSON(http.StatusOK, nil)
}

// Return a list of trust status for all containers
// (GET /container/status)
func (s *RasServer) GetContainerStatus(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return a trust status for given container
// (GET /container/status/{uuid})
func (s *RasServer) GetContainerStatusUuid(ctx echo.Context, uuid string) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return briefing info for the given container
// (GET /container/{uuid})
func (s *RasServer) GetContainerUuid(ctx echo.Context, uuid string) error {
	return ctx.JSON(http.StatusOK, nil)
}

// create info for a container
// (POST /container/{uuid})
func (s *RasServer) PostContainerUuid(ctx echo.Context, uuid string) error {
	return ctx.JSON(http.StatusOK, nil)
}

// put a container into given status
// (PUT /container/{uuid})
func (s *RasServer) PutContainerUuid(ctx echo.Context, uuid string) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return the base value of a given device
// (GET /device/basevalue/{id})
func (s *RasServer) GetDeviceBasevalueId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// create/update the base value of the given device
// (PUT /device/basevalue/{id})
func (s *RasServer) PutDeviceBasevalueId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return a list of trust status for all devices
// (GET /device/status)
func (s *RasServer) GetDeviceStatus(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return a trust status for given device
// (GET /device/status/{id})
func (s *RasServer) GetDeviceStatusId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return briefing info for the given device
// (GET /device/{id})
func (s *RasServer) GetDeviceId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// create info for a device
// (POST /device/{id})
func (s *RasServer) PostDeviceId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// put a device into given status
// (PUT /device/{id})
func (s *RasServer) PutDeviceId(ctx echo.Context, id int64) error {
	return ctx.JSON(http.StatusOK, nil)
}

// Return the trust report for the given server
// (GET /report/{serverId})
func (s *RasServer) GetReportServerId(ctx echo.Context, serverId int64) error {
	s.cm.Lock()
	c := s.cm.GetCache(serverId)
	s.cm.Unlock()

	if c == nil {
		return ctx.JSON(http.StatusNotFound, nil)
	}

	report, err := trustmgr.GetLatestReportById(serverId)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}

	return ctx.JSON(http.StatusOK, *report)
}

type ServerBriefInfo struct {
	ClientId   int64
	Ip         string
	Registered bool
}

// Return a list of briefing info for all servers
// (GET /server)
func (s *RasServer) GetServer(ctx echo.Context) error {
	//get server briefing info from sql
	cids, err := trustmgr.GetAllClientID()
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	briefinfo := []ServerBriefInfo{}
	var infoName []string
	infoName = append(infoName, "ip")
	for _, v := range cids {
		rc, err := trustmgr.GetRegisterClientById(v)
		if err != nil {
			return ctx.JSON(http.StatusNoContent, err)
		}
		rt, err := trustmgr.GetClientInfoByID(v, infoName)
		if err != nil {
			fmt.Println("not found ip")
		}
		briefinfo = append(briefinfo, ServerBriefInfo{ClientId: rc.ClientID, Ip: rt["ip"], Registered: rc.IsDeleted})
	}

	return ctx.JSON(http.StatusOK, briefinfo)
}

// put a list of servers into given status
// (PUT /server)
func (s *RasServer) PutServer(ctx echo.Context) error {
	var serverBody PutServerJSONBody
	err := ctx.Bind(&serverBody)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	cids := *serverBody.Clientids
	if serverBody.Registered != nil {
		for _, cid := range cids {
			err = trustmgr.UpdateRegisterStatusById(cid, !*serverBody.Registered)
			if err != nil {
				return ctx.JSON(http.StatusForbidden, nil)
			}
		}
	}
	return nil
}

// Return the base value of a given server
// (GET /server/basevalue/{serverId})
func (s *RasServer) GetServerBasevalueServerId(ctx echo.Context, serverId int64) error {
	meInfo, err := trustmgr.GetBaseValueById(serverId)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, nil)
	}
	return ctx.JSON(http.StatusOK, meInfo)
}

// create/update the base value of the given server
// (PUT /server/basevalue/{serverId})
func (s *RasServer) PutServerBasevalueServerId(ctx echo.Context, serverId int64) error {
	var serverBvBody PutServerBasevalueServerIdJSONBody
	err := ctx.Bind(&serverBvBody)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	mInfo, err := trustmgr.GetBaseValueById(serverId)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	modifyManifest(mInfo, *serverBvBody.Measurements)
	modifyPcrValue(mInfo, *serverBvBody.Pcrvalues)
	err = trustmgr.SaveBaseValueById(serverId, mInfo)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	return nil
}

func modifyManifest(mInfo *entity.MeasurementInfo, ms []Measurement) {
	var mf entity.Measurement
	for i := range ms {
		if i < len(mInfo.Manifest) {
			mInfo.Manifest[i].Name = *ms[i].Name
			mInfo.Manifest[i].Type = string(*ms[i].Type)
			mInfo.Manifest[i].Value = *ms[i].Value
		} else {
			mf.Name = *ms[i].Name
			mf.Type = string(*ms[i].Type)
			mf.Value = *ms[i].Value
			mInfo.Manifest = append(mInfo.Manifest, mf)
		}
	}
}

func modifyPcrValue(mInfo *entity.MeasurementInfo, pValues []PcrValue) {
	for _, con := range pValues {
		mInfo.PcrInfo.Values[*con.Index] = *con.Value
	}
}

type ServerTrustStatus struct {
	ClientID int64
	Status   string
}

// Return a list of trust status for all servers
// (GET /status)
func (s *RasServer) GetStatus(ctx echo.Context) error {
	// get server status list from cache
	s.cm.Lock()
	ts := s.cm.GetAllTrustStatus()
	s.cm.Unlock()
	status := make([]ServerTrustStatus, 0, len(ts))
	for key, s := range ts {
		status = append(status, ServerTrustStatus{ClientID: key, Status: s})
	}
	return ctx.JSON(http.StatusOK, status)
}

// Return a trust status for given server
// (GET /status/{serverId})
func (s *RasServer) GetStatusServerId(ctx echo.Context, serverId int64) error {
	return nil
}

// Return the version of current API
// (GET /version)
func (s *RasServer) GetVersion(ctx echo.Context) error {

	return ctx.JSON(http.StatusOK, "0.1.0")
}

func NewRasServer(cm *cache.CacheMgr) *RasServer {
	return &RasServer{cm: cm}
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

func StartServer(addr string, cm *cache.CacheMgr) {
	router := echo.New()

	// FIXME: need to be replaced with a formal authenticator implementation
	v, err := internal.NewFakeAuthenticator(config.GetDefault(config.ConfServer).GetAuthKeyFile())
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

	server := NewRasServer(cm)
	RegisterHandlers(router, server)

	router.Logger.Fatal(router.Start(addr))
}
