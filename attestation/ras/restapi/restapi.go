/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3/yemaolin/wanghaijing
Create: 2021-09-17
Description: provide rest api to outside to control ras server.
	1. 2022-02-17	wucaijun
		refine the rest api structure to support both application/json and
		text/plain, make api more readable.


The following comments are just for test and make the rest api understand easily.

curl -X POST -H "Accept: application/json" -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40002/
curl -X POST -H "Content-type: application/json" -d "{'name':'Joe', 'email':'joe@example.com'}" http://localhost:40002/
curl -X GET -H "Content-type: application/json" http://localhost:40002/
curl -X GET http://localhost:40002/

GET /version            显示当前rest api版本信息
POST /login             采用账号密码方式登录的入口
GET/POST /config        对RAS进行运行时配置的入口
GET /                   显示所有server的基本信息
GET /{from}/{to}        显示指定从from到to的server的基本信息

GET     /{id}                   显示指定server的基本信息
POST    /{id}                   修改指定server的基本信息
DELETE  /{id}                   删除指定server
GET     /{id}/reports           显示指定server的所有可信报告
GET     /{id}/reports/{rid}     显示指定server的指定可信报告
DELETE  /{id}/reports/{rid}     删除指定server的指定可信报告
GET     /{id}/basevalues        显示指定server的所有基准值
POST    /{id}/basevalues        新增指定server的基准值
GET     /{id}/basevalues/{bid}  显示指定server的指定基准值
POST    /{id}/basevalues/{bid}  修改指定server的指定基准值
DELETE  /{id}/basevalues/{bid}  删除指定server的指定基准值
*/

// restapi package provides the restful api interface based on openapi standard.
package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/middleware"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwt"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/internal"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

const (
	// (GET /)
	htmlAllList = `<html><head><title>All Nodes Information</title>
	<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
	</head><body><script>$(document).ready(function(){$("button").click(function(){
	$.ajax({
		url:this.value,
		type:"POST",
		contentType: "application/json",
		/*this need to change true or false by registerd*/
		data: {"registered":true} 
		success:function(result,status,xhr)
	{if(status=="success"){location.reload(true);}},});});});</script>
	<script>function logout(){localStorage.setItem("token", null);alert("logout successfully");}</script>
	<a href="/login">login</a>&emsp;
	<a href="javascript:void(0)" onclick="logout()">logout</a>&emsp;
	<a href="/version">version</a>&emsp;<a href="/config">config</a><br/><table border="1">
	<tr align="center" bgcolor="#00FF00"><th>ID</th><th>RegTime</th>
	<th>Online</th><th>IP Address</th><th>Trusted</th><th>Info</th><th>Trust Reports</th>
	<th>Base Values</th><th>IsAutoUpdate</th><th>Registered</th><th>Action</th></tr>`
	htmlListInfo = `<tr align="center"><td>%d</td><td>%s</td><td>%v</td><td>%s</td>
	<td>%v</td><td><a href="/%d">link</a></td><td><a href="/%d/reports">link</a></td>
	<td><a href="/%d/basevalues">link</a></td><td>%v</td><td>%v</td>
	<td><button type="button" value="/%d">%s</button></td></tr>`
	htmlListEnd = `</table></body></html>`

	// login
	htmlLogin = `<html><head><title>login</title>
<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
<body><script>$(document).ready(function(){$("#login").click(function(){var token = $("#token").val();
localStorage.setItem("token", token);alert("save token successful");})})</script>
<div><input type="token" name="token" id ="token" placeholder="please enter the token here"></div>
<div><input type="button" id="login" value="login" ></div></body></html>`

	// (GET /config)
	htmlConfig = `<html><head><title>Config Setting</title></head><body>
<a href="/">Back</a><br/><table border="1"><form action="/config" method="post">
<tr align="center" bgcolor="#00FF00"><th>Parameter</th><th>Value</th></tr>`
	htmlConfigEdit = `<tr><td>%s</td><td align="center">
<input type="text" name="%s" value="%d"/></td></tr>`
	htmlConfigEnd = `</table><input type="submit" value="Save"/></form></body></html>`

	// (GET /version)
	htmlVersion = `<html><head><title>Version</title></head><body>
<a href="/">Back</a><br/>Version: %s</body></html>`

	// (GET /{id})
	htmlOneNode = `<html><head><title>One Node Information</title></head><body>
<a href="/">Back</a><br/><table border="1">
<tr align="center" bgcolor="#00FF00"><th>Parameter</th><th>Value</th></tr>`
	htmlNodeInfo = `<tr><td>%s</td><td align="center">%v</td></tr>`
	htmlTableEnd = `</table></body></html>`

	// (GET /{id}/basevalues)
	htmlListBaseValues = `<html><head><title>Base Values List</title>
<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<script>$(document).ready(function(){$("button").click(function(){$.ajax({url:this.value,
type:"DELETE",success:function(result,status,xhr){if(status=="success"){location.reload(true);
}},});});});</script><a href="/">Back</a>&emsp;<a href="/%d/newbasevalue">Add</a><br/>
<table border="1"><tr align="center" bgcolor="#00FF00">
<th>Index</th><th>Create Time</th><th>Name</th><th>Enabled</th><th>Verified</th>
<th>Trusted</th><th>Pcr</th><th>Bios</th><th>Ima</th><th>Action</th></tr>`
	htmlBaseValueInfo = `<tr><td>%d</td><td>%s</td><td>%s</td><td>%v</td>
<td>%v</td><td>%v</td><td><a href="/%d/basevalues/%d">Link</a></td>
<td><a href="/%d/basevalues/%d">Link</a></td><td><a href="/%d/basevalues/%d">Link</a></td>
<td><button type="button" value="/%d/basevalues/%d">Delete</button></td></tr>`

	// (GET /{id}/basevalues/{basevalueid})
	htmlOneBaseValue = `<html><head><title>Base Value Detail</title></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<a href="/%d/basevalues">Back</a><br/><table border="1"><tr align="center" bgcolor="#00FF00">
<th>Parameter</th><th>Value</th></tr>`
	htmlBaseValue = `<tr><td align="center">%s</td><td>%v</td></tr>`

	// (GET /{id}/newbasevalue)
	htmlNewBaseValue = `<html><head><title>New Base Value</title></head><body>
<a href="/%d/basevalues">Back</a><br/>
<form action="/%d/newbasevalue" method="post" enctype="multipart/form-data">
<table border="1"><tr align="center" bgcolor="#00FF00">
<th>Parameter</th><th>Value</th></tr>
<tr><td>Name</td><td><input type="text" name="Name" /></td></tr>
<tr><td>Enabled</td><td><select name="Enabled"><option value ="true">True</option>
<option value ="false">False</option></select></td></tr>
<tr><td>PCR Base Value File</td><td><input type="file" name="Pcr" /></td></tr>
<tr><td>BIOS Base Value File</td><td><input type="file" name="Bios" /></td></tr>
<tr><td>IMA Base Value File</td><td><input type="file" name="Ima" /></td></tr>
</table><br/><input type="submit" value="Save" /></form></body></html>`

	// (GET /{id}/reports)
	htmlListReports = `<html><head><title>Trust Reports List</title>
<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<script>$(document).ready(function(){$("button").click(function(){$.ajax({url:this.value,
type:"DELETE",success:function(result,status,xhr){if(status=="success"){location.reload(true);
}},});});});</script><a href="/">Back</a><br/><b>Client %d Trust Reports List</b><br/>
<table border="1"><tr align="center" bgcolor="#00FF00"><th>Index</th><th>Create Time</th>
<th>Validated</th><th>Trusted</th><th>Details</th><th>Action</th></tr>`
	htmlReportInfo = `<tr align="center"><td>%d</td><td>%s</td><td>%v</td>
<td>%v</td><td><a href="/%d/reports/%d">Link</a></td><td>
<button type="button" value="/%d/reports/%d">Delete</button></td></tr>`

	// (GET /{id}/reports/{reportid})
	htmlOneReport = `<html><head><title>Trust Report Detail</title></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<a href="/%d/reports">Back</a><br/><table border="1"><tr align="center" bgcolor="#00FF00">
<th>Parameter</th><th>Value</th></tr>`
	htmlReportValue = `<tr><td align="center">%s</td><td>%v</td></tr>`

	strHBDuration     = `Heart Beat Duration(s)`
	nameHBDuration    = `hbduration`
	strTrustDuration  = `Trust Report Duration(s)`
	nameTrustDuration = `trustduration`
	strReportID       = `Report ID`
	strRegTime        = `Register Time`
	strCreateTime     = `Create Time`
	strOnline         = `Online`
	strNull           = ``
	strTrusted        = `trusted`
	strUnknown        = "unknown"
	strUntrusted      = "untrusted"
	strNotFound       = "not found"
	strValidated      = `Validated`
	strQuoted         = `Quoted`
	strSignature      = `Signature`
	strPcrLog         = `PcrLog`
	strBiosLog        = `BiosLog`
	strImaLog         = `ImaLog`
	strClientID       = `clientid`
	strBaseType       = `baseType`
	strUuid           = `uuid`
	strContainer      = "container"
	strDevice         = "device"
	strName           = "name"
	strEnabled        = "enabled"
	strIsAutoUpdate   = "isAutoUpdate"
	strRegistered     = "registered"
	strVerified       = "Verified"
	strPCR            = "pcr"
	strBIOS           = "bios"
	strIMA            = "ima"
	strBaseValueID    = `BaseValue ID`
	errNoClient       = `rest api error: %v`
	errParseWrong     = "parse parameters failed!"

	strDeleteClientSuccess    = `delete client %d success`
	strDeleteReportSuccess    = `delete client %d report %d success`
	strDeleteReportFail       = `delete client %d report %d fail, %v`
	strDeleteBaseValueSuccess = `delete client %d base value %d success`
	strDeleteBaseValueFail    = `delete client %d base value %d fail, %v`
)

type MyRestAPIServer struct {
}

type JsonResult struct {
	Result string
}

func StartServer(https bool) {
	if !https {
		//https off ,use http protocol
		StartServerHttp(config.GetRestPort())
	} else {
		//https on
		StartServerHttps(config.GetHttpsPort())
	}
}

func StartServerHttp(port string) {
	e := echo.New()
	// TODO: need to be replaced with a formal authenticator implementation
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
	e.Use(av)
	RegisterHandlers(e, &MyRestAPIServer{})
	logger.L.Sugar().Debug(e.Start(port))
}

func StartServerHttps(httpsPort string) {
	e := echo.New()
	// TODO: need to be replaced with a formal authenticator implementation
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
	e.Use(av)
	RegisterHandlers(e, &MyRestAPIServer{})
	e.Logger.Fatal(e.StartTLS(httpsPort, config.GetHttpsKeyCertFile(), config.GetHttpsPrivateKeyFile()))
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

func CreateTestAuthToken() ([]byte, error) {
	authKeyPubFile := config.GetAuthKeyFile()
	authKeyFile := os.TempDir() + "/at" + strconv.FormatInt(rand.Int63(), 16)
	test.CreateAuthKeyFile(authKeyFile, authKeyPubFile)
	defer os.Remove(authKeyFile)

	v, err := internal.NewFakeAuthenticator(authKeyFile)
	if err != nil {
		logger.L.Sugar().Errorf("Create Authenticator failed")
		return nil, err
	}

	// create a JWT with config write & server write permission
	writeJWT, err := v.CreateJWSWithClaims([]string{"write:config", "write:servers"})
	if err != nil {
		logger.L.Sugar().Errorf("Create Token failed")
		return nil, err
	}

	return writeJWT, nil
}

func genAllListHtml(nodes map[int64]*typdefs.NodeInfo) string {
	var buf bytes.Buffer
	var button string
	buf.WriteString(htmlAllList)
	for _, n := range nodes {
		if n.Registered {
			button = "Unregister"
		} else {
			button = "Register"
		}
		buf.WriteString(fmt.Sprintf(htmlListInfo, n.ID, n.RegTime,
			n.Online, n.IPAddress, n.Trusted, n.ID, n.ID, n.ID, n.IsAutoUpdate, n.Registered, n.ID, button))
	}
	buf.WriteString(htmlListEnd)
	return buf.String()
}

func showListNodesByRange(ctx echo.Context, from, to int64) error {
	nodes, err := trustmgr.GetAllNodes(from, to)
	if checkJSON(ctx) {
		if err != nil {
			logger.L.Sugar().Debugf(errNoClient, err)
			return ctx.JSON(http.StatusNotFound, map[int64]*typdefs.NodeInfo{})
		}
		return ctx.JSON(http.StatusOK, nodes)
	}
	if err != nil {
		logger.L.Sugar().Debugf(errNoClient, err)
		return ctx.HTML(http.StatusNotFound, "")
	}
	return ctx.HTML(http.StatusOK, genAllListHtml(nodes))
}

// (GET /)
// get all nodes information
//  read all nodes information as html
//    curl -X GET http://localhost:40002
//  read all nodes information as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002
func (s *MyRestAPIServer) Get(ctx echo.Context) error {
	return showListNodesByRange(ctx, math.MinInt64, math.MaxInt64)
}

// TODO: add more parameters in this struct to export to outside control.
type cfgRecord struct {
	HBDuration      time.Duration `json:"hbduration" form:"hbduration"`
	TrustDuration   time.Duration `json:"trustduration" form:"trustduration"`
	IsAllupdate     *bool         `json:"isallupdate" form:"isallupdate"`
	LogTestMode     *bool         `json:"logtestmode" form:"logtestmode"`
	DBHost          string
	DBName          string
	DBPassword      string
	DBPort          int
	DBUser          string
	DigestAlgorithm string
	MgrStrategy     string
	ExtractRules    string
}

func genConfigJson() *cfgRecord {
	return &cfgRecord{
		HBDuration:      config.GetHBDuration() / time.Second,
		TrustDuration:   config.GetTrustDuration() / time.Second,
		IsAllupdate:     config.GetIsAllUpdate(),
		LogTestMode:     config.GetLoggerMode(),
		DBHost:          config.GetDBHost(),
		DBName:          config.GetDBName(),
		DBPassword:      config.GetDBPassword(),
		DBPort:          config.GetDBPort(),
		DBUser:          config.GetDBUser(),
		DigestAlgorithm: config.GetDigestAlgorithm(),
		MgrStrategy:     config.GetMgrStrategy(),
		ExtractRules:    getExtractRules(),
	}
}

func getExtractRules() string {
	e := config.GetExtractRules()
	res, err := json.Marshal(e)
	if err != nil {
		log.Print("Unmarshal struct to string failed.")
		return ""
	}
	return string(res)
}
func genConfigHtml() string {
	var buf bytes.Buffer
	buf.WriteString(htmlConfig)
	buf.WriteString(fmt.Sprintf(htmlConfigEdit, strHBDuration,
		nameHBDuration, config.GetHBDuration()/time.Second))
	buf.WriteString(fmt.Sprintf(htmlConfigEdit, strTrustDuration,
		nameTrustDuration, config.GetTrustDuration()/time.Second))
	buf.WriteString(htmlConfigEnd)
	return buf.String()
}

// (GET /config)
// get ras server configuration
//  read config as html
//    curl -X GET http://localhost:40002/config
//  read config as json
//    curl -k -X GET -H "Content-type: application/json" https://localhost:40003/config
func (s *MyRestAPIServer) GetConfig(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson())
	}
	return ctx.HTML(http.StatusOK, genConfigHtml())
}

// (POST /config)
// modify ras server configuration
//  write config as html/form
//    curl -X POST -d "hbduration=20" -d "trustduration=30"  -d"isallupdate=true" http://localhost:40002/config
//  write config as json
//    curl -X POST -H "Content-type: application/json" -d '{"hbduration": 100, "trustduration": 200, "isallupdate": true}' http://localhost:40002/config
// Notice: key name must be enclosed by "" in json format!!!
func (s *MyRestAPIServer) PostConfig(ctx echo.Context) error {
	cfg := new(cfgRecord)
	cfg.IsAllupdate = config.GetIsAllUpdate()
	cfg.LogTestMode = config.GetLoggerMode()
	err := ctx.Bind(cfg)
	if err != nil {
		logger.L.Sugar().Debugf(errNoClient, err)
		return err
	}
	configSet(cfg)
	configDBSet(cfg)
	trustmgr.UpdateAllNodes()
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson())
	}
	return ctx.HTML(http.StatusOK, genConfigHtml())
}

func configSet(cfg *cfgRecord) {
	if cfg.HBDuration != 0 {
		config.SetHBDuration(cfg.HBDuration * time.Second)
	}
	if cfg.TrustDuration != 0 {
		config.SetTrustDuration(cfg.TrustDuration * time.Second)
	}
	if cfg.IsAllupdate != nil && *cfg.IsAllupdate {
		trustmgr.UpdateCaches()
	}
	if cfg.LogTestMode != nil && *cfg.LogTestMode != *config.GetLoggerMode() {
		config.SetLoggerMode(*cfg.LogTestMode)
	}
	if cfg.DigestAlgorithm == typdefs.Sha1AlgStr || cfg.DigestAlgorithm == typdefs.Sha256AlgStr || cfg.DigestAlgorithm == typdefs.Sm3AlgStr {
		config.SetDigestAlgorithm(cfg.DigestAlgorithm)
	}
	if cfg.MgrStrategy == config.AutoStrategy || cfg.MgrStrategy == config.ManualStrategy {
		config.SetMgrStrategy(cfg.MgrStrategy)
	}
	if cfg.ExtractRules != strNull {
		config.SetExtractRules(cfg.ExtractRules)
	}
}

func configDBSet(cfg *cfgRecord) {
	if cfg.DBHost != strNull {
		config.SetDBHost(cfg.DBHost)
	}
	if cfg.DBName != strNull {
		config.SetDBName(cfg.DBName)
	}
	if cfg.DBPassword != strNull {
		config.SetDBPassword(cfg.DBPassword)
	}
	if cfg.DBPort != 0 {
		config.SetDBPort(cfg.DBPort)
	}
	if cfg.DBUser != strNull {
		config.SetDBUser(cfg.DBUser)
	}
}

// (GET /login)
// login/logout ras server as admin
func (s *MyRestAPIServer) GetLogin(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, htmlLogin)
	}
	return ctx.HTML(http.StatusOK, htmlLogin)
}

// (GET /version)
// get ras server version information
//  read version as html
//    curl -X GET http://localhost:40002/version
//  read version as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/version
func (s *MyRestAPIServer) GetVersion(ctx echo.Context) error {
	if checkJSON(ctx) {
		res := struct {
			Version string
		}{
			config.RasVersion,
		}
		return ctx.JSON(http.StatusOK, res)
	}
	res := fmt.Sprintf(htmlVersion, config.RasVersion)
	return ctx.HTML(http.StatusOK, res)
}

// (GET /{from}/{to})
// get nodes information from "from" node to "to" node sequentially
//  read a range nodes info as html
//    curl -X GET http://localhost:40002/{from}/{to}
//  read a range nodes info as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/{from}/{to}
func (s *MyRestAPIServer) GetFromTo(ctx echo.Context, from int64, to int64) error {
	return showListNodesByRange(ctx, from, to)
}

// (DELETE /{id})
// delete node {id}
//  delete a node by html
//    curl -X DELETE http://localhost:40002/{id}
//  delete a node by json
//    curl -X DELETE -H "Content-type: application/json" http://localhost:40002/{id}
func (s *MyRestAPIServer) DeleteId(ctx echo.Context, id int64) error {
	trustmgr.UnRegisterClientByID(id)
	if checkJSON(ctx) {
		res := JsonResult{}
		res.Result = fmt.Sprintf(strDeleteClientSuccess, id)
		return ctx.JSON(http.StatusOK, res)
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(strDeleteClientSuccess, id))
}

// TODO: add more information of the node
func genNodeHtml(c *cache.Cache) string {
	var buf bytes.Buffer
	buf.WriteString(htmlOneNode)
	buf.WriteString(fmt.Sprintf(htmlNodeInfo, strRegTime, c.GetRegTime()))
	buf.WriteString(fmt.Sprintf(htmlNodeInfo, strOnline, c.GetOnline()))
	buf.WriteString(fmt.Sprintf(htmlNodeInfo, strTrusted, c.GetTrusted()))
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id})
// get node {id} information
//  read node {id} info as html
//    curl -X GET http://localhost:40002/{id}
//  read node {id} info as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}
func (s *MyRestAPIServer) GetId(ctx echo.Context, id int64) error {
	cr, err1 := trustmgr.FindClientByID(id)
	c, err2 := trustmgr.GetCache(id)
	if checkJSON(ctx) {
		if err1 != nil {
			logger.L.Sugar().Debugf(errNoClient, err1)
			return ctx.JSON(http.StatusNotFound, &typdefs.NodeInfo{ID: id})
		}
		ni := typdefs.NodeInfo{
			ID:           id,
			RegTime:      cr.RegTime.String(),
			Registered:   false,
			Online:       false,
			Trusted:      cache.StrUnknown,
			IsAutoUpdate: false,
			IPAddress:    typdefs.GetIP(),
		}
		if err2 == nil {
			ni.Registered = true
			ni.Online = c.GetOnline()
			ni.Trusted = c.GetTrusted()
			ni.IsAutoUpdate = c.GetIsAutoUpdate()
		}
		return ctx.JSON(http.StatusOK, &ni)
	}
	if err1 != nil {
		logger.L.Sugar().Debugf(errNoClient, err1)
		return ctx.JSON(http.StatusNotFound, "")
	}
	return ctx.HTML(http.StatusOK, genNodeHtml(c))
}

type clientInfo struct {
	Registered   *bool `json:"registered"`
	IsAutoUpdate *bool `json:"isautoupdate"`
}

// (POST /{id})
// modify node {id} information
//  modify node {id} information by json
//    curl -X POST -H "Content-type: multipart/form-data" -F "IsAutoUpdate=true;type=application/json" http://localhost:40002/{id}
func (s *MyRestAPIServer) PostId(ctx echo.Context, id int64) error {
	cinfo := new(clientInfo)
	err := ctx.Bind(cinfo)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	cr, err1 := trustmgr.FindClientByID(id)
	if err1 != nil {
		return ctx.JSON(http.StatusNotFound, "client not found!")
	}

	if cinfo.Registered != nil && !cr.Registered && *cinfo.Registered {
		trustmgr.RegisterClientByID(id, cr.RegTime, cr.IKCert)
	} else if cinfo.Registered != nil && cr.Registered && !*cinfo.Registered {
		trustmgr.UnRegisterClientByID(id)
	}
	c, err := trustmgr.GetCache(id)
	if err == nil {
		if cinfo.IsAutoUpdate != nil && *cinfo.IsAutoUpdate != c.GetIsAutoUpdate() {
			c.SetIsAutoUpdate(*cinfo.IsAutoUpdate)
		}
	} else {
		return ctx.JSON(http.StatusNotModified, "modify cache failed!")
	}

	res := fmt.Sprintf("change server %d information", id)
	return ctx.JSON(http.StatusOK, res)
}

func genBaseValuesHtml(id int64, rows []*typdefs.BaseRow) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlListBaseValues, id))
	for _, n := range rows {
		buf.WriteString(fmt.Sprintf(htmlBaseValueInfo, n.ID,
			n.CreateTime.Format(typdefs.StrTimeFormat), n.Name, n.Enabled,
			n.Verified, n.Trusted, id, n.ID, id, n.ID, id, n.ID, id, n.ID))
	}
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id}/basevalues)
// get node {id} all base values
func (s *MyRestAPIServer) GetIdBasevalues(ctx echo.Context, id int64) error {
	rows, err := trustmgr.FindBaseValuesByClientID(id)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, rows)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, genBaseValuesHtml(id, rows))
}

// (DELETE /{id}/basevalues/{basevalueid})
// delete node {id} one base value {basevalueid}
func (s *MyRestAPIServer) DeleteIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	err := trustmgr.DeleteBaseValueByID(basevalueid)
	if checkJSON(ctx) {
		res := JsonResult{}
		if err != nil {
			res.Result = fmt.Sprintf(strDeleteBaseValueFail, id, basevalueid, err)
			return ctx.JSON(http.StatusOK, res)
		}
		res.Result = fmt.Sprintf(strDeleteBaseValueSuccess, id, basevalueid)
		return ctx.JSON(http.StatusOK, res)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(strDeleteBaseValueSuccess, id, basevalueid))
}

func genBaseValueHtml(basevalue *typdefs.BaseRow) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlOneBaseValue, basevalue.ClientID))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strBaseValueID, basevalue.ID))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strCreateTime,
		basevalue.CreateTime.Format(typdefs.StrTimeFormat)))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strName, basevalue.Name))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strEnabled, basevalue.Enabled))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strVerified, basevalue.Verified))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strTrusted, basevalue.Trusted))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strPCR, basevalue.Pcr))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strBIOS, basevalue.Bios))
	buf.WriteString(fmt.Sprintf(htmlBaseValue, strIMA, basevalue.Ima))
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id}/basevalues/{basevalueid})
// get node {id} one base value {basevalueid}
func (s *MyRestAPIServer) GetIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	row, err := trustmgr.FindBaseValueByID(basevalueid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, row)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, genBaseValueHtml(row))
}

// (POST /{id}/basevalues/{basevalueid})
// modify node {id} one base value {basevalueid}
//    curl -X POST -H "Content-type: multipart/form-data" -F "ClientID=XX"  -F "BaseType=XX" -F "Name=XX" -F "Enabled=true" -F "Pcr=@./filename" -F "Bios=@./filename" -F "Ima=@./filename" http://localhost:40002/{uuid}/device/basevalue
//  save node {id} a new base value by json
//    curl -X POST -k -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/{id}/basevalues/{basevalueid} --data '{"enabled":true}'
// 因为这里只需要传enabled一个参数，所以不需要检查其是否为空,默认为false
func (s *MyRestAPIServer) PostIdBasevaluesBasevalueid(ctx echo.Context, cid, bid int64) error {
	if checkJSON(ctx) {
		bv := new(baseValueJson)
		err := ctx.Bind(bv)
		if err != nil {
			return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
		}
		c, err := trustmgr.GetCache(cid)
		if err != nil {
			return err
		}
		for _, base := range c.Bases {
			if base.ID == bid {
				base.Enabled = bv.Enabled
			}
		}
		trustmgr.ModifyEnabledByID(bid, bv.Enabled)
		return ctx.JSON(http.StatusFound, fmt.Sprintf("server id:%d, basevalueid:%d, modify enabled=%t", cid, bid, bv.Enabled))
	}
	sEnv := ctx.FormValue(strEnabled)
	enabled, _ := strconv.ParseBool(sEnv)
	c, err := trustmgr.GetCache(cid)
	if err != nil {
		return err
	}
	for _, base := range c.Bases {
		if base.ID == bid {
			base.Enabled = enabled
		}
	}
	trustmgr.ModifyEnabledByID(bid, enabled)
	return ctx.HTML(http.StatusFound, "") //这里应该需要鑫淼更新网页端修改，网页端显示基准值的页面应该有一个按钮，点击就会把该基准值的enabled字段修改一次.
}

func genNewBaseValueHtml(id int64) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlNewBaseValue, id, id))
	return buf.String()
}

// (GET /{id}/newbasevalue)
//  get a empty page as html for new base value, no need for json!!!
//    curl -X GET http://localhost:40002/{id}/newbasevalue
func (s *MyRestAPIServer) GetIdNewbasevalue(ctx echo.Context, id int64) error {
	return ctx.HTML(http.StatusOK, genNewBaseValueHtml(id))
}

func (s *MyRestAPIServer) getFile(ctx echo.Context, name string) (string, error) {
	param, err := ctx.FormFile(name)
	if err != nil {
		return "", err
	}
	file, err := param.Open()
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type baseValueJson struct {
	BaseType   string `json:"basetype"`
	Uuid       string `json:"uuid"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Pcr        string `json:"pcr"`
	Bios       string `json:"bios"`
	Ima        string `json:"ima"`
	IsNewGroup bool   `json:"isnewgroup"` // TRUE represent this request will create a new group of base value, otherwise it just be added in an existing base value group. This field must be contained in the request!
}

// (POST /{id}/newbasevalue)
//  save node {id} a new base value by html
//    curl -X POST -H "Content-type: multipart/form-data" -F "Name=XX" -F "Enabled=true" -F "Pcr=@./filename" -F "Bios=@./filename" -F "Ima=@./filename" http://localhost:40002/1/newbasevalue
//  save node {id} a new base value by json
//    curl -X POST -H "Content-Type: application/json" -k https://localhost:40003/{id}/newbasevalue -d '{"name":"test", "enabled":true, "pcr":"pcr value", "bios":"bios value", "ima":"ima value", "isnewgroup":false}'
func (s *MyRestAPIServer) PostIdNewbasevalue(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return s.postBValueByJson(ctx, id)
	}
	return s.postBValueByMultiForm(ctx, id)
}

func (s *MyRestAPIServer) postBValueByJson(ctx echo.Context, id int64) error {
	bv := new(baseValueJson)
	err := ctx.Bind(bv)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}
	row := &typdefs.BaseRow{
		ClientID:   id,
		BaseType:   bv.BaseType,
		Uuid:       bv.Uuid,
		CreateTime: time.Now(),
		Name:       bv.Name,
		Enabled:    bv.Enabled,
		Pcr:        bv.Pcr,
		Bios:       bv.Bios,
		Ima:        bv.Ima,
	}
	if bv.IsNewGroup {
		// set other base value records' enabled field to false.
		// TODO: need a interface to do the above operation!
		c, err := trustmgr.GetCache(id)
		if err == nil {
			for _, base := range c.Bases {
				base.Enabled = false
			}
		}
		trustmgr.DisableBaseByClientID(id)
		logger.L.Debug("set other base value records' enabled field to false...")
	}
	trustmgr.SaveBaseValue(row)
	return ctx.JSON(http.StatusOK, "add a new base value ok!")
}

func (s *MyRestAPIServer) postBValueByMultiForm(ctx echo.Context, id int64) error {
	name := ctx.FormValue(strName)
	baseType := ctx.FormValue(strBaseType)
	uuid := ctx.FormValue(strUuid)
	sEnv := ctx.FormValue(strEnabled)
	enabled, _ := strconv.ParseBool(sEnv)
	pcr, err := s.getFile(ctx, strPCR)
	if err != nil && err != http.ErrMissingFile {
		return err
	}
	bios, err := s.getFile(ctx, strBIOS)
	if err != nil && err != http.ErrMissingFile {
		return err
	}
	ima, err := s.getFile(ctx, strIMA)
	if err != nil && err != http.ErrMissingFile {
		return err
	}
	row := &typdefs.BaseRow{
		ClientID:   id,
		BaseType:   baseType,
		Uuid:       uuid,
		CreateTime: time.Now(),
		Name:       name,
		Enabled:    enabled,
		Pcr:        pcr,
		Bios:       bios,
		Ima:        ima,
	}
	trustmgr.SaveBaseValue(row)
	/* // no use???
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusFound, row)
	}
	*/
	return ctx.Redirect(http.StatusFound, fmt.Sprintf("/%d/basevalues", id))
}

func genReportsHtml(id int64, rows []typdefs.ReportRow) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlListReports, id))
	for _, n := range rows {
		buf.WriteString(fmt.Sprintf(htmlReportInfo, n.ID,
			n.CreateTime.Format(typdefs.StrTimeFormat), n.Validated,
			n.Trusted, n.ClientID, n.ID, n.ClientID, n.ID))
	}
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id}/reports)
// get node {id} all reports
//  get node {id} all reports as html
//    curl -X GET http://localhost:40002/{id}/reports
//  get node {id} all reports as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}/reports
func (s *MyRestAPIServer) GetIdReports(ctx echo.Context, id int64) error {
	rows, err := trustmgr.FindReportsByClientID(id)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, rows)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, genReportsHtml(id, rows))
}

// (DELETE /{id}/reports/{reportid})
// delete node {id} one report {reportid}
//  delete node {id} report {reportid} by html
//    curl -X DELETE http://localhost:40002/{id}/reports/{reportid}
//  delete node {id} report {reportid} by json
//    curl -X DELETE -H "Content-type: application/json" http://localhost:40002/{id}/reports/{reportid}
func (s *MyRestAPIServer) DeleteIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	err := trustmgr.DeleteReportByID(reportid)
	if checkJSON(ctx) {
		res := JsonResult{}
		if err != nil {
			res.Result = fmt.Sprintf(strDeleteReportFail, id, reportid, err)
			return ctx.JSON(http.StatusOK, res)
		}
		res.Result = fmt.Sprintf(strDeleteReportSuccess, id, reportid)
		return ctx.JSON(http.StatusOK, res)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(strDeleteReportSuccess, id, reportid))
}

func genReportHtml(report *typdefs.ReportRow) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlOneReport, report.ClientID))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strReportID, report.ID))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strCreateTime,
		report.CreateTime.Format(typdefs.StrTimeFormat)))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strValidated, report.Validated))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strTrusted, report.Trusted))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strQuoted, report.Quoted))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strSignature, report.Signature))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strPcrLog, report.PcrLog))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strBiosLog, report.BiosLog))
	buf.WriteString(fmt.Sprintf(htmlReportValue, strImaLog, report.ImaLog))
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id}/reports/{reportid})
// get node {id} one report {reportid}
//  get node {id} report {reportid} as html
//    curl -X GET http://localhost:40002/{id}/reports/{reportid}
//  get node {id} report {reportid} as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}/reports/{reportid}
func (s *MyRestAPIServer) GetIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	row, err := trustmgr.FindReportByID(reportid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, row)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, genReportHtml(row))
}

// Return a list of trust status for all containers of a given client
// (GET /{id}/container/status)
func (s *MyRestAPIServer) GetIdContainerStatus(ctx echo.Context, cid int64) error {
	c, err := trustmgr.GetCache(cid)
	if err != nil {
		return err
	}
	rows := c.Bases
	var buf bytes.Buffer
	for i := 0; i < len(rows); i++ {
		if rows[i].BaseType != strContainer {
			continue
		}
		var status string
		if !rows[i].Verified {
			status = strUnknown
		} else {
			if rows[i].Trusted && !time.Now().After(c.GetTrustExpiration()) { //Verified and not timed out
				status = strTrusted
			} else if !rows[i].Trusted {
				status = strUntrusted
			} else {
				status = strUnknown
			}
		}
		buf.WriteString(fmt.Sprintf("%s : %s\n", rows[i].Uuid, status))
	}

	return ctx.JSON(http.StatusOK, buf.String())
}

// Return a list of trust status for all devices of a given client
// (GET /{id}/device/status)
func (s *MyRestAPIServer) GetIdDeviceStatus(ctx echo.Context, cid int64) error {
	c, err := trustmgr.GetCache(cid)
	if err != nil {
		return err
	}
	rows := c.Bases
	var buf bytes.Buffer
	for i := 0; i < len(rows); i++ {
		if rows[i].BaseType != strDevice {
			continue
		}
		var status string
		if !rows[i].Verified {
			status = strUnknown
		} else {
			if rows[i].Trusted && !time.Now().After(c.GetTrustExpiration()) {
				status = strTrusted
			} else {
				status = strUntrusted
			}
		}
		buf.WriteString(fmt.Sprintf("%s : %s\n", rows[i].Uuid, status))
	}

	return ctx.JSON(http.StatusOK, buf.String())
}
