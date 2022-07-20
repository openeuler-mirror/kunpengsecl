package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	echolog "github.com/labstack/gommon/log"
	"github.com/lestrrat-go/jwx/jwt"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
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
	byteER, err := json.Marshal(er)
	if err != nil {
		log.Print("Marshal extract rules to []byte failed.")
		return ctx.JSON(http.StatusForbidden, err)
	}
	strER := string(byteER)
	auc := cfg.GetAutoUpdateConfig()
	byteAUC, err := json.Marshal(auc)
	if err != nil {
		log.Print("Marshal auto update config to []byte failed.")
		return ctx.JSON(http.StatusForbidden, err)
	}
	strAUC := string(byteAUC)
	cfgMap := map[string]string{
		"dbHost":           cfg.GetHost(),
		"dbName":           cfg.GetDBName(),
		"dbUser":           cfg.GetUser(),
		"dbPort":           fmt.Sprint(cfg.GetDBPort()),
		"mgrStrategy":      cfg.GetMgrStrategy(),
		"changeTime":       fmt.Sprint(cfg.GetChangeTime()),
		"extractRules":     strER,
		"hbDuration":       fmt.Sprint(cfg.GetHBDuration()),
		"trustDuration":    fmt.Sprint(cfg.GetTrustDuration()),
		"digestAlgorithm":  cfg.GetDigestAlgorithm(),
		"autoUpdateConfig": strAUC,
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
		log.Print("Bind configBody failed.\n")
		return ctx.JSON(http.StatusNoContent, err)
	}
	postCfgMap := map[string]func(s string){
		"dbHost":           func(s string) { cfg.SetHost(s) },
		"dbName":           func(s string) { cfg.SetDBName(s) },
		"dbUser":           func(s string) { cfg.SetUser(s) },
		"dbPort":           func(s string) { setDBport(s) },
		"dbPassword":       func(s string) { cfg.SetPassword(s) },
		"mgrStrategy":      func(s string) { cfg.SetMgrStrategy(s) },
		"extractRules":     func(s string) { setExtractRules(s) },
		"hbDuration":       func(s string) { setHBDuration(s) },
		"trustDuration":    func(s string) { setTDuration(s) },
		"digestAlgorithm":  func(s string) { setDigestAlgorithm(s) },
		"autoUpdateConfig": func(s string) { setAUConfig(s) },
	}
	if len(configBody) == 0 {
		log.Print("Not have specification about the config items that need modified.\n")
	}
	for i := range configBody {
		doFunc, ok := postCfgMap[*configBody[i].Name]
		if ok {
			doFunc(*configBody[i].Value)
		} else {
			log.Print("Modify config failed.\n")
		}
	}
	return ctx.JSON(http.StatusOK, nil)
}

//Modify some config information respectively
func setDBport(val string) {
	cfg := config.GetDefault(config.ConfServer)
	port, err := strconv.Atoi(val)
	if err != nil {
		log.Print("Convert string to int failed.")
		return
	}
	cfg.SetDBPort(port)
}

func setExtractRules(val string) {
	cfg := config.GetDefault(config.ConfServer)
	byteER := []byte(val)
	var extractRules entity.ExtractRules
	err := json.Unmarshal(byteER, &extractRules)
	if err != nil {
		log.Print("Unmarshal byte to struct failed.")
		return
	}
	cfg.SetExtractRules(extractRules)
}

func setHBDuration(val string) {
	cfg := config.GetDefault(config.ConfServer)
	duration, err := time.ParseDuration(val)
	if err != nil {
		log.Print("Convert string to duration failed.")
		return
	}
	if duration == cfg.GetHBDuration() {
		log.Print("Set same config value for HBDuration, ignored.")
		return
	}
	cfg.SetHBDuration(duration)
	server.cm.SyncConfig()
}

func setTDuration(val string) {
	cfg := config.GetDefault(config.ConfServer)
	duration, err := time.ParseDuration(val)
	if err != nil {
		log.Print("Convert string to duration failed.")
		return
	}
	if duration == cfg.GetTrustDuration() {
		log.Print("Set same config value for TrustDuration, ignored.")
		return
	}
	cfg.SetTrustDuration(duration)
	server.cm.SyncConfig()
}

func setDigestAlgorithm(val string) {
	cfg := config.GetDefault(config.ConfServer)
	if val == cfg.GetDigestAlgorithm() {
		log.Print("Set same config value for DigestAlgorithm, ignored.")
		return
	}
	cfg.SetDigestAlgorithm(val)
	server.cm.SyncConfig()
}

func setAUConfig(val string) {
	cfg := config.GetDefault(config.ConfServer)
	byteAUC := []byte(val)
	var autoUpdateConfig entity.AutoUpdateConfig
	err := json.Unmarshal(byteAUC, &autoUpdateConfig)
	if err != nil {
		log.Print("Unmarshal byte to struct failed.")
		return
	}
	cfg.SetAutoUpdateConfig(autoUpdateConfig)
}

// Return the base value of a given container
// (GET /container/basevalue/{uuid})
func (s *RasServer) GetContainerBasevalueUuid(ctx echo.Context, uuid string) error {
	cbv, err := trustmgr.GetContainerBaseValueByUUId(uuid)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, err)
	}
	return ctx.JSON(http.StatusOK, cbv)
}

// create/update the base value of the given container
// (PUT /container/basevalue/{uuid})
func (s *RasServer) PutContainerBasevalueUuid(ctx echo.Context, uuid string) error {
	var body PutContainerBasevalueUuidJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	cbv := map[string]string{}
	for _, m := range *body.Measurements {
		cbv[*m.Name] = *m.Value
	}
	err = trustmgr.AddContainerBaseValue(&entity.ContainerBaseValue{
		ContainerUUID: uuid,
		Value:         cbv,
	})
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	return ctx.JSON(http.StatusOK, nil)
}

// Return a list of trust status for all containers
// (GET /container/status)
func (s *RasServer) GetContainerStatus(ctx echo.Context) error {
	s.cm.Lock()
	ts, err := s.cm.GetAllContainerTrustStatus()
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	s.cm.Unlock()
	status := make([]ContainerTrustStatus, 0, len(ts))
	for key, statu := range ts {
		status = append(status, ContainerTrustStatus{UUID: key, Status: statu})
	}
	return ctx.JSON(http.StatusOK, status)
}

type ContainerTrustStatus struct {
	UUID   string
	Status string
}

type DeviceTrustStatus struct {
	deviceId int64
	Status   string
}

// Return a trust status for given container
// (GET /container/status/{uuid})
func (s *RasServer) GetContainerStatusUuid(ctx echo.Context, uuID string) error {
	s.cm.Lock()
	ts := s.cm.GetContainerTrustStatusByUUId(uuID)
	s.cm.Unlock()
	return ctx.JSON(http.StatusOK, ContainerTrustStatus{UUID: uuID, Status: ts})
}

// Return briefing info for the given container
// (GET /container/{uuid})
func (s *RasServer) GetContainerUuid(ctx echo.Context, uuID string) error {
	c, err := trustmgr.GetContainerByUUId(uuID)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, err)
	}
	return ctx.JSON(http.StatusOK, c)
}

// create info for a container
// (POST /container/{uuid})
func (s *RasServer) PostContainerUuid(ctx echo.Context, uuID string) error {
	var body PostContainerUuidJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	c := entity.Container{
		UUID:     *body.Uuid,
		ClientId: *body.Serverid,
		Online:   true,
		Deleted:  !*body.Registered,
	}
	err = trustmgr.AddContainer(&c)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	return ctx.JSON(http.StatusOK, nil)
}

// put a container into given status
// (PUT /container/{uuid})
func (s *RasServer) PutContainerUuid(ctx echo.Context, uuID string) error {
	var body PutContainerUuidJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	if result, ok := body.(bool); ok {
		trustmgr.UpdateContainerStatusByUUId(uuID, !result)
		return ctx.JSON(http.StatusOK, nil)
	}
	return ctx.JSON(http.StatusNoContent, fmt.Errorf("put container failed"))
}

// Return the base value of a given device
// (GET /device/basevalue/{id})
func (s *RasServer) GetDeviceBasevalueId(ctx echo.Context, id int64) error {
	dbv, err := trustmgr.GetDeviceBaseValueById(id)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, err)
	}
	return ctx.JSON(http.StatusOK, dbv)
}

// create/update the base value of the given device
// (PUT /device/basevalue/{id})
func (s *RasServer) PutDeviceBasevalueId(ctx echo.Context, id int64) error {
	var body PutDeviceBasevalueIdJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	dbv := map[string]string{}
	for _, m := range *body.Measurements {
		dbv[*m.Name] = *m.Value
	}
	err = trustmgr.AddDeviceBaseValue(&entity.PcieBaseValue{
		DeviceID: id,
		Value:    dbv,
	})
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	return ctx.JSON(http.StatusOK, nil)
}

// Return a list of trust status for all devices
// (GET /device/status)
func (s *RasServer) GetDeviceStatus(ctx echo.Context) error {
	s.cm.Lock()
	ts, err := s.cm.GetAllDeviceTrustStatus()
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	s.cm.Unlock()
	status := make([]DeviceTrustStatus, 0, len(ts))
	for key, s := range ts {
		status = append(status, DeviceTrustStatus{deviceId: key, Status: s})
	}
	return ctx.JSON(http.StatusOK, status)
}

// Return a trust status for given device
// (GET /device/status/{id})
func (s *RasServer) GetDeviceStatusId(ctx echo.Context, id int64) error {
	s.cm.Lock()
	ts := s.cm.GetDeviceTrustStatusById(id)
	s.cm.Unlock()
	return ctx.JSON(http.StatusOK, DeviceTrustStatus{deviceId: id, Status: ts})
}

// Return briefing info for the given device
// (GET /device/{id})
func (s *RasServer) GetDeviceId(ctx echo.Context, id int64) error {
	d, err := trustmgr.GetDeviceById(id)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, err)
	}
	return ctx.JSON(http.StatusOK, d)
}

// create info for a device
// (POST /device/{id})
func (s *RasServer) PostDeviceId(ctx echo.Context, id int64) error {
	var body PostDeviceIdJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	d := entity.PcieDevice{
		ID:       *body.Id,
		ClientId: *body.Serverid,
		Online:   true,
		Deleted:  !*body.Registered,
	}
	err = trustmgr.AddDevice(&d)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	return ctx.JSON(http.StatusOK, nil)
}

// put a device into given status
// (PUT /device/{id})
func (s *RasServer) PutDeviceId(ctx echo.Context, id int64) error {
	var body PutDeviceIdJSONBody
	err := ctx.Bind(&body)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, err)
	}
	if result, ok := body.(bool); ok {
		err = trustmgr.UpdateDeviceStatusById(id, !result)
		if err != nil {
			return ctx.JSON(http.StatusNoContent, err)
		}
		return ctx.JSON(http.StatusOK, nil)
	}
	return ctx.JSON(http.StatusNoContent, fmt.Errorf("put device failed"))
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
			log.Println("not found ip")
		}
		briefinfo = append(briefinfo, ServerBriefInfo{ClientId: rc.ClientID, Ip: rt["ip"], Registered: !rc.IsDeleted})
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
			if *serverBody.Registered {
				s.cm.Lock()
				defer s.cm.Unlock()

				s.cm.CreateCache(cid)
			} else {
				s.cm.Lock()
				defer s.cm.Unlock()

				c := s.cm.GetCache(cid)
				if c != nil {
					log.Printf("delete %d", cid)
					s.cm.RemoveCache(cid)
				}
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
	mInfo := entity.MeasurementInfo{}
	mInfo.PcrInfo.Values = make(map[int]string, 8)
	modifyManifest(&mInfo, *serverBvBody.Measurements)
	modifyPcrValue(&mInfo, *serverBvBody.Pcrvalues)
	err = trustmgr.SaveBaseValueById(serverId, &mInfo)
	if err != nil {
		return ctx.JSON(http.StatusNoContent, nil)
	}
	return nil
}

func modifyManifest(mInfo *entity.MeasurementInfo, ms []Measurement) {
	var mf entity.Measurement
	for i := range ms {
		mf.Name = *ms[i].Name
		mf.Type = string(*ms[i].Type)
		mf.Value = *ms[i].Value
		mInfo.Manifest = append(mInfo.Manifest, mf)
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
	s.cm.Lock()
	ts := s.cm.GetTrustStatusById(serverId)
	s.cm.Unlock()
	return ctx.JSON(http.StatusOK, ServerTrustStatus{ClientID: serverId, Status: ts})
}

// Return the version of current API
// (GET /version)
func (s *RasServer) GetVersion(ctx echo.Context) error {

	return ctx.JSON(http.StatusOK, "1.0.0")
}

var server *RasServer

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
					// ignore the not used template paramenter
					_ = ctx
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

	// TODO: need to be replaced with a formal authenticator implementation
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

	server = NewRasServer(cm)
	RegisterHandlers(router, server)

	if *config.VerboseFlag {
		router.Logger.SetLevel(echolog.DEBUG)
	} else {
		router.Logger.SetLevel(echolog.ERROR)
	}
	router.Logger.Fatal(router.Start(addr))
}

func CreateTestAuthToken() ([]byte, error) {
	authKeyPubFile := config.GetDefault(config.ConfServer).GetAuthKeyFile()
	authKeyFile := os.TempDir() + "/at" + strconv.FormatInt(rand.Int63(), 16)
	test.CreateAuthKeyFile(authKeyFile, authKeyPubFile)
	defer os.Remove(authKeyFile)

	v, err := internal.NewFakeAuthenticator(authKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Create Authenticator failed: %v", err)
	}

	// create a JWT with config write & server write permission
	writeJWT, err := v.CreateJWSWithClaims([]string{"write:config", "write:servers"})
	if err != nil {
		return nil, fmt.Errorf("Create token failed: %v", err)
	}

	return writeJWT, nil
}
