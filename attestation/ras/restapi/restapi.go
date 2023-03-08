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
	"regexp"
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
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/rim"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi/test"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
)

const (
	// (GET /)
	htmlAllList = `<html><head><title>All Nodes Information</title>
	<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
	</head><body><script>
	$(document).ready(function(){
	$("button").click(function(){
	var postList;
	if(this.innerText=="Register"){postList={
	  "registered": true
	};}
	if(this.innerText=="Unregister"){postList={
	  "registered": false
	};}
	$.ajaxSettings.beforeSend = function(request){
		request.setRequestHeader("Authorization",localStorage.getItem("token"));
		};
	$.ajax({
		url:this.value,
		type:"POST",
		contentType: "application/json",
		data:JSON.stringify(postList),
		success:function(result,status,xhr){if(status=="success"){location.reload(true);}},
		error:function(XMLHttpRequest, textStatus, errorThrown){
				alert("请求对象XMLHttpRequest: "+XMLHttpRequest);
				alert("错误类型textStatus: "+textStatus);
				alert("异常对象errorThrown: "+errorThrown);}
	});});});</script>
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
	<body>
	<script>
	$(document).ready(function(){$("#login").click(function(){var token = $("#token").val();
		localStorage.setItem("token", token);
		alert("save token successful");})})
		//xhr.setRequestHeader("Authorization", localStorage.getItem("token"));
	</script>
	<div><input type="token" name="token" id ="token" placeholder="please enter the token here"></div>
	<div><input type="button" id="login" value="login" ></div></body></html>`

	// (GET /config)
	htmlConfig = `<html><head><title>Config Setting</title></head><body>
<a href="/">Back</a><br/><table border="1"><form action="/config" method="post">
<tr align="center" bgcolor="#00FF00"><th>Parameter</th><th>Value</th></tr>`
	htmlConfigEdit = `<tr><td>%s</td><td align="center">
<input type="text" name="%s" value="%s"/></td></tr>`
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
	<script>$(document).ready(function(){
	$("#change").click(function(){
	var postList;
	if(this.innerText=="Enable"){postList={
	  "Enabled": true
	};}
	if(this.innerText=="Disable"){postList={
	  "Enabled": false
	};}
	$.ajaxSettings.beforeSend = function(request){
		request.setRequestHeader("Authorization",localStorage.getItem("token"));
		};
	$.ajax({
		url:this.value,
		type:"POST",
		contentType: "application/json",
		data:JSON.stringify(postList),
		success:function(result,status,xhr){if(status=="success"){location.reload(true);}},
		error:function(XMLHttpRequest, textStatus, errorThrown){
				alert("请求对象XMLHttpRequest: "+XMLHttpRequest);
				alert("错误类型textStatus: "+textStatus);
				alert("异常对象errorThrown: "+errorThrown);}
	});});
	$("#delete").click(function(){
	$.ajaxSettings.beforeSend = function(request){
	request.setRequestHeader("Authorization",localStorage.getItem("token"));};
	$.ajax({url:this.value,
	type:"DELETE",success:function(result,status,xhr){if(status=="success"){location.reload(true);
	}},});});});</script><a href="/">Back</a>&emsp;<a href="/%d/newbasevalue">Add</a><br/>
	<table border="1"><tr align="center" bgcolor="#00FF00">
	<th>Index</th><th>Create Time</th><th>Name</th><th>Enabled</th><th>Verified</th>
	<th>Trusted</th><th>Pcr</th><th>Bios</th><th>Ima</th><th>Action</th></tr>`
	htmlBaseValueInfo = `<tr><td>%d</td><td>%s</td><td>%s</td><td>%v<button type="button" value="/%d/basevalues/%d" id="change">%s</button></td>
	<td>%v</td><td>%v</td><td><a href="/%d/basevalues/%d">Link</a></td>
	<td><a href="/%d/basevalues/%d">Link</a></td><td><a href="/%d/basevalues/%d">Link</a></td>
	<td><button type="button" value="/%d/basevalues/%d" id="delete">Delete</button></td></tr>`

	// (GET /{id}/basevalues/{basevalueid})
	htmlOneBaseValue = `<html><head><title>Base Value Detail</title></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<a href="/%d/basevalues">Back</a><br/><table border="1"><tr align="center" bgcolor="#00FF00">
<th>Parameter</th><th>Value</th></tr>`
	htmlBaseValue = `<tr><td align="center">%s</td><td>%v</td></tr>`

	// (GET /{id}/newbasevalue)
	htmlNewBaseValue = `<!DOCTYPE html>
	<html><head><title>New Base Value</title></head>
	<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
	<body>
	<script>
	$(document).ready(function(){$("#submit").click(function(){$.ajaxSettings.beforeSend = function(request){
		request.setRequestHeader("Authorization",localStorage.getItem("token"));
		};
	$.ajax({
		type: $("#form").attr("method"),
		url: $("#form").attr("action"),
		data: $('#form').serialize(),
		success: function () {
			alert("save successfully！");
		},
		error : function() {
			alert("save failed！");
		}
	});})})</script>
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
	</table><br/><input type="button" value="Save" id="submit"></form></body></html>`

	// (GET /{id}/reports)
	htmlListReports = `<html><head><title>Trust Reports List</title>
<script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script></head><body>
<style type="text/css">td{white-space: pre-line;}</style>
<script>$(document).ready(function(){$("button").click(function(){
$.ajaxSettings.beforeSend = function(request){request.setRequestHeader("Authorization",localStorage.getItem("token"));};
$.ajax({url:this.value,type:"DELETE",success:function(result,status,xhr){if(status=="success"){location.reload(true);
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

	// (GET /{id}/ta/{tauuid}/newtabasevalue)
	// TODO
	htmlNewTaBaseValue = "NewTaBaseValue, id:%d, tauuid:%s\n"

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
	strIsNewGroup     = "isNewGroup"
	strIsAutoUpdate   = "isAutoUpdate"
	strRegistered     = "registered"
	strVerified       = "Verified"
	strPCR            = "pcr"
	strBIOS           = "bios"
	strIMA            = "ima"
	strBaseValueID    = `BaseValue ID`
	strVInfo          = "valueinfo"
	errNoClient       = `rest api error: %v`
	errParseWrong     = "parse parameters failed!"

	strDeleteClientSuccess      = `delete client %d success`
	strDeleteReportSuccess      = `delete client %d report %d success`
	strDeleteReportFail         = `delete client %d report %d fail, %v`
	strDeleteBaseValueSuccess   = `delete client %d base value %d success`
	strDeleteBaseValueFail      = `delete client %d base value %d fail, %v`
	strDeleteTaReportSuccess    = `delete client %d ta %s report %d success`
	strDeleteTaReportFail       = `delete client %d ta %s report %d fail, %v`
	strDeleteTaBaseValueSuccess = `delete client %d ta %s base value %d success`
	strDeleteTaBaseValueFail    = `delete client %d ta %s base value %d fail, %v`
	strDisableBaseByClientID    = "set other base value records' enabled field to false..."
	strDisableTaBaseByUuid      = "set other ta base value records' enabled field to false..."
	strGetTaStatus              = "trust status of ta %s : %s"
)

// MyRestAPIServer means rest api server
type MyRestAPIServer struct {
}

// JsonResult means result in json format
type JsonResult struct {
	Result string
}

var (
	srv *echo.Echo = nil
)

// StartServer starts a server.
func StartServer(https bool) {
	if !https {
		//https off ,use http protocol
		StartServerHttp(config.GetRestPort())
	} else {
		//https on
		StartServerHttps(config.GetHttpsPort())
	}
}

// StartServerHttp starts a http server to provide reat api services.
func StartServerHttp(port string) {
	if srv != nil {
		return
	}
	srv = echo.New()
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
	if srv == nil {
		return
	}
	srv.Use(av)
	RegisterHandlers(srv, &MyRestAPIServer{})
	logger.L.Sugar().Debug(srv.Start(port))
}

// StartServerHttps starts a https server to provide reat api services.
func StartServerHttps(httpsPort string) {
	if srv != nil {
		return
	}
	srv = echo.New()
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
	if srv == nil {
		return
	}
	srv.Use(av)
	RegisterHandlers(srv, &MyRestAPIServer{})
	logger.L.Sugar().Debug(srv.StartTLS(httpsPort, config.GetHttpsKeyCertFile(), config.GetHttpsPrivateKeyFile()))
}

// StopServer stops stops the server.
func StopServer() {
	if srv == nil {
		return
	}
	srv.Close()
	srv = nil
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

// CreateAuthValidator creates auth validator in order to start the server smoothly.
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

func checkXML(ctx echo.Context) bool {
	cty := ctx.Request().Header.Get(echo.HeaderContentType)
	if cty == echo.MIMETextXML || cty == echo.MIMETextXMLCharsetUTF8 {
		return true
	}
	return false
}

// CreateTestAuthToken creates test auth token and returns token.
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

// Get gets all nodes information
//
//	read all nodes information as html
//	  curl -X GET http://localhost:40002
//	read all nodes information as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002
func (s *MyRestAPIServer) Get(ctx echo.Context) error {
	return showListNodesByRange(ctx, math.MinInt64, math.MaxInt64)
}

// TODO: add more parameters in this struct to export to outside control.
type cfgRecord struct {
	HBDuration      string `json:"hbduration" form:"hbduration"`
	TrustDuration   string `json:"trustduration" form:"trustduration"`
	IsAllupdate     *bool  `json:"isallupdate" form:"isallupdate"`
	LogTestMode     *bool  `json:"logtestmode" form:"logtestmode"`
	DigestAlgorithm string `json:"digestalgorithm" form:"digestalgorithm"`
	MgrStrategy     string `json:"mgrstrategy" form:"mgrstrategy"`
	ExtractRules    string `json:"extractrules" form:"extractrules"`
	TaVerifyType    int    `json:"taverifytype" form:"taverifytype"`
}

func genConfigJson() *cfgRecord {
	return &cfgRecord{
		HBDuration:      config.GetHBDuration().String(),
		TrustDuration:   config.GetTrustDuration().String(),
		IsAllupdate:     config.GetIsAllUpdate(),
		LogTestMode:     config.GetLoggerMode(),
		DigestAlgorithm: config.GetDigestAlgorithm(),
		MgrStrategy:     config.GetMgrStrategy(),
		ExtractRules:    getExtractRules(),
		TaVerifyType:    config.GetTaVerifyType(),
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
		nameHBDuration, config.GetHBDuration().String()))
	buf.WriteString(fmt.Sprintf(htmlConfigEdit, strTrustDuration,
		nameTrustDuration, config.GetTrustDuration().String()))
	buf.WriteString(htmlConfigEnd)
	return buf.String()
}

// (GET /config)

// GetConfig gets ras server configuration
//
//	read config as html
//	  curl -X GET http://localhost:40002/config
//	read config as json
//	  curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/config
func (s *MyRestAPIServer) GetConfig(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson())
	}
	return ctx.HTML(http.StatusOK, genConfigHtml())
}

// (POST /config)

// PostConfig modifies ras server configuration
//
//	write config as html/form
//	  curl -X POST -d "hbduration=10s" -d "trustduration=2m0s"  -d"isallupdate=true" http://localhost:40002/config
//	write config as json
//	  curl -X POST -k -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" -d '{"hbduration":"10s", "trustduration":"2m0s", "isallupdate": true}' https://localhost:40003/config
//
// Notice: key name must be enclosed by "" in json format!!!
func (s *MyRestAPIServer) PostConfig(ctx echo.Context) error {
	cfg := new(cfgRecord)
	cfg.IsAllupdate = config.GetIsAllUpdate()
	cfg.LogTestMode = config.GetLoggerMode()
	cfg.TaVerifyType = config.GetTaVerifyType()
	err := ctx.Bind(cfg)
	if err != nil {
		logger.L.Sugar().Debugf(errNoClient, err)
		return err
	}
	configSet(cfg)
	trustmgr.UpdateAllNodes()
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson())
	}
	return ctx.HTML(http.StatusOK, genConfigHtml())
}

func configSet(cfg *cfgRecord) {
	hbd, _ := time.ParseDuration(cfg.HBDuration)
	td, _ := time.ParseDuration(cfg.TrustDuration)
	if cfg.HBDuration != strNull {
		config.SetHBDuration(hbd)
	}
	if cfg.TrustDuration != strNull {
		config.SetTrustDuration(td)
	}
	if cfg.IsAllupdate != nil && *cfg.IsAllupdate {
		trustmgr.UpdateCaches()
	}
	if cfg.LogTestMode != nil && *cfg.LogTestMode != *config.GetLoggerMode() {
		config.SetLoggerMode(*cfg.LogTestMode)
	}
	if cfg.DigestAlgorithm == typdefs.Sha1AlgStr ||
		cfg.DigestAlgorithm == typdefs.Sha256AlgStr ||
		cfg.DigestAlgorithm == typdefs.Sm3AlgStr {
		config.SetDigestAlgorithm(cfg.DigestAlgorithm)
	}
	if cfg.MgrStrategy == config.AutoStrategy || cfg.MgrStrategy == config.ManualStrategy {
		config.SetMgrStrategy(cfg.MgrStrategy)
	}
	if cfg.ExtractRules != strNull {
		config.SetExtractRules(cfg.ExtractRules)
	}
	if cfg.TaVerifyType == 1 || cfg.TaVerifyType == 2 || cfg.TaVerifyType == 3 {
		config.SetTaVerifyType(cfg.TaVerifyType)
	}
}

// (GET /login)

// GetLogin gets login/logout ras server as admin information.
func (s *MyRestAPIServer) GetLogin(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, htmlLogin)
	}
	return ctx.HTML(http.StatusOK, htmlLogin)
}

// (GET /version)

// GetVersion gets ras server version information
//
//	read version as html
//	  curl -X GET http://localhost:40002/version
//	read version as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/version
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

// GetFromTo gets nodes information from "from" node to "to" node sequentially
//
//	read a range nodes info as html
//	  curl -X GET http://localhost:40002/{from}/{to}
//	read a range nodes info as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/{from}/{to}
func (s *MyRestAPIServer) GetFromTo(ctx echo.Context, from int64, to int64) error {
	return showListNodesByRange(ctx, from, to)
}

// (DELETE /{id})

// DeleteId delete node {id}
//
//	delete a node by html
//	  curl -X DELETE http://localhost:40002/{id}
//	delete a node by json
//	  curl -X DELETE -H "Content-type: application/json" http://localhost:40002/{id}
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

// GetId gets node {id} information
//
//	read node {id} info as html
//	  curl -X GET http://localhost:40002/{id}
//	read node {id} info as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}
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

// PostId modifies node {id} information
//
//	modify node {id} information by json
//	  curl -X POST -H "Content-type: multipart/form-data" -F "IsAutoUpdate=true;type=application/json" http://localhost:40002/{id}
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
	var changeButton string
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlListBaseValues, id))
	for _, n := range rows {
		if n.Enabled {
			changeButton = "Disable"
		} else {
			changeButton = "Enable"
		}
		buf.WriteString(fmt.Sprintf(htmlBaseValueInfo, n.ID,
			n.CreateTime.Format(typdefs.StrTimeFormat), n.Name, n.Enabled, id, n.ID, changeButton,
			n.Verified, n.Trusted, id, n.ID, id, n.ID, id, n.ID, id, n.ID))
	}
	buf.WriteString(htmlTableEnd)
	return buf.String()
}

// (GET /{id}/basevalues)

// GetIdBasevalues gets node {id} all base values
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

// DeleteIdBasevaluesBasevalueid deletes node {id} one base value {basevalueid}.
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

// GetIdBasevaluesBasevalueid gets node {id} one base value {basevalueid}
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

// PostIdBasevaluesBasevalueid modifies node {id} one base value {basevalueid}
//
//	  curl -X POST -H "Content-type: multipart/form-data" -F "ClientID=XX"  -F "BaseType=XX" -F "Name=XX" -F "Enabled=true" -F "Pcr=@./filename" -F "Bios=@./filename" -F "Ima=@./filename" http://localhost:40002/{uuid}/device/basevalue
//	save node {id} a new base value by json
//	  curl -X POST -k -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/{id}/basevalues/{basevalueid} --data '{"enabled":true}'
//
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
		return ctx.JSON(
			http.StatusFound,
			fmt.Sprintf("server id:%d, basevalueid:%d, modify enabled=%t", cid, bid, bv.Enabled))
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
	return ctx.HTML(http.StatusFound, "")
}

func genNewBaseValueHtml(id int64) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlNewBaseValue, id, id))
	return buf.String()
}

// (GET /{id}/newbasevalue)

// GetIdNewbasevalue gets a empty page as html for new base value, no need for json!!!
//	  curl -X GET http://localhost:40002/{id}/newbasevalue
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
	BaseType string `json:"basetype"`
	Uuid     string `json:"uuid"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Pcr      string `json:"pcr"`
	Bios     string `json:"bios"`
	Ima      string `json:"ima"`
	// TRUE represent this request will create a new group of base value,
	// otherwise it just be added in an existing base value group. This field must be contained in the request!
	IsNewGroup bool `json:"isnewgroup"`
}

type tabaseValueJson struct {
	Uuid      string `json:"uuid"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Valueinfo string `json:"valueinfo"`
}

// (POST /{id}/newbasevalue)

// PostIdNewbasevalue save node {id} a new base value by html
//	  curl -X POST -H "Content-type: multipart/form-data" -F "Name=XX" -F "Enabled=true" -F "Pcr=@./filename" -F "Bios=@./filename" -F "Ima=@./filename" http://localhost:40002/1/newbasevalue
//	save node {id} a new base value by json
//
// (pcr,bios,ima的赋值要经过安全检查，不满足的会发出解析错误，可以参考attestation\test\integration\manual_mode_test.sh的测试样例)
//
//		  curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -k https://localhost:40003/{id}/newbasevalue -d '{"name":"test", "enabled":true,"isnewgroup":false}'
//		save node {id} a new base value by xml
//	 (a simple base RIM file according to TCG Reference Integrity Manifest (RIM) Information Model
//	 https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model_v1p01_r0p16_pub.pdf)
//		  curl -X POST -H "Content-Type: text/xml" -k https://localhost:40003/{id}/newbasevalue -d [Signed base RIM according to TCG RIM spec]
func (s *MyRestAPIServer) PostIdNewbasevalue(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return s.postBValueByJson(ctx, id)
	}
	if checkXML(ctx) {
		return s.postBValueByXml(ctx, id)
	}
	return s.postBValueByMultiForm(ctx, id)
}

func (s *MyRestAPIServer) postBValueByXml(ctx echo.Context, id int64) error {
	bvXml := make([]byte, ctx.Request().ContentLength)
	_, err := ctx.Request().Body.Read(bvXml)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	ima, err := rim.ParseRIM(bvXml, config.GetRimRootCert(), config.GetDigestAlgorithm())
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	row := &typdefs.BaseRow{
		ClientID:   id,
		CreateTime: time.Now(),
		Enabled:    true,
		Ima:        ima,
		BaseType:   typdefs.StrHost,
	}

	// set other base value records' enabled field to false.
	c, err := trustmgr.GetCache(id)
	if err == nil {
		for _, base := range c.Bases {
			base.Enabled = false
		}
	}
	err = trustmgr.DisableBaseByClientID(id)
	if err != nil {
		logger.L.Debug("disable base by id failed. " + err.Error())
	}

	logger.L.Debug(strDisableBaseByClientID)

	trustmgr.SaveBaseValue(row)
	return ctx.JSON(http.StatusOK, "add a new base value by RIM OK!")
}

// 这三个正则表达式用于对新添加的基准值的pcr,bios，ima做安全检查，只有符合相应规则的值才能被正确解析并添加
var (
	// 匹配一个多行字符串，每行可以是一个空行，
	// 或者每行以 1 到 2 个数字开头，后面跟着 40 到 128 个十六进制数字，最后以换行符结束。
	reBvPcr = regexp.MustCompile(`(?m)\A\z|\A(^[0-9]{1,2} [[:xdigit:]]{40,128}\n)+\z`)
	// 匹配一个多行字符串，每行可以是一个空行，
	// 或者每行以 "ima-ng (sha1|sha256|sm3):" 或 "ima" 开头，后面跟着 40 到 64 个十六进制数字，
	// 最后以一个或多个打印字符（包括空格和换行符）结束
	reBvIma = regexp.MustCompile(`(?m)\A\z|\A(^(ima-ng (sha1|sha256|sm3):[[:xdigit:]]{40,64}|ima [[:xdigit:]]{40}) [[:print:]]+\n)+\z`)
	// 匹配一个多行字符串，每行可以是一个空行，
	// 或者每行以 1 到 8 个十六进制数字、一个连字符和一个或多个数字开头，后面跟着 40 个十六进制数字、一个空格和 "sha256:"，
	// 然后是 64 个十六进制数字，最后是 "N/A" 或 "sm3:" 和 64 个十六进制数字，最后以换行符结束。
	reBvBios = regexp.MustCompile(`(?m)\A\z|\A(^[[:xdigit:]]{1,8}-[0-9]+ [[:xdigit:]]{40} sha256:[[:xdigit:]]{64} (N/A|sm3:[[:xdigit:]]{64})\n)+\z`)
)

func (s *MyRestAPIServer) postBValueByJson(ctx echo.Context, id int64) error {
	bv := new(baseValueJson)
	err := ctx.Bind(bv)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	if !reBvPcr.MatchString(bv.Pcr) || !reBvBios.MatchString(bv.Bios) || !reBvIma.MatchString(bv.Ima) {
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
		logger.L.Debug(strDisableBaseByClientID)
	}
	trustmgr.SaveBaseValue(row)
	return ctx.JSON(http.StatusOK, "add a new base value ok!")
}

func (s *MyRestAPIServer) postBValueByMultiForm(ctx echo.Context, id int64) error {
	name := ctx.FormValue(strName)
	baseType := ctx.FormValue(strBaseType)
	uuid := ctx.FormValue(strUuid)
	sEnv := ctx.FormValue(strEnabled)
	sIsNewGroup := ctx.FormValue(strIsNewGroup)
	enabled, _ := strconv.ParseBool(sEnv)
	isNewGroup, _ := strconv.ParseBool(sIsNewGroup)
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
	if isNewGroup {
		// set other base value records' enabled field to false.
		// TODO: need a interface to do the above operation!
		c, err := trustmgr.GetCache(id)
		if err == nil {
			for _, base := range c.Bases {
				base.Enabled = false
			}
		}
		trustmgr.DisableBaseByClientID(id)
		logger.L.Debug(strDisableBaseByClientID)
	}
	trustmgr.SaveBaseValue(row)
	/* // no use???
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusFound, row)
	}
	*/
	return ctx.Redirect(http.StatusFound, fmt.Sprintf("/%d/basevalues", id))
}

func (s *MyRestAPIServer) postTaBValueByXml(ctx echo.Context, id int64, tauuid string) error {
	bvXml := make([]byte, ctx.Request().ContentLength)
	_, err := ctx.Request().Body.Read(bvXml)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	row := &typdefs.TaBaseRow{
		ClientID:   id,
		Uuid:       tauuid,
		CreateTime: time.Now(),
	}
	//TODO: 从rim中获取bv.valueinfo和bv.name

	// set other base value records' enabled field to false.
	err = trustmgr.DisableTaBaseByUuid(id, tauuid)
	if err != nil {
		logger.L.Debug("disable ta base by id failed. " + err.Error())
	}

	logger.L.Debug(strDisableTaBaseByUuid)

	trustmgr.SaveTaBaseValue(row)
	return ctx.JSON(http.StatusOK, "add a new ta base value OK!")
}

func (s *MyRestAPIServer) postTaBValueByJson(ctx echo.Context, id int64, tauuid string) error {
	bv := new(tabaseValueJson)
	err := ctx.Bind(bv)
	if err != nil {
		return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
	}

	row := &typdefs.TaBaseRow{
		ClientID:   id,
		Uuid:       tauuid,
		CreateTime: time.Now(),
		Name:       bv.Name,
		Valueinfo:  []byte(bv.Valueinfo),
	}

	trustmgr.DisableTaBaseByUuid(id, tauuid)
	logger.L.Debug(strDisableTaBaseByUuid)

	trustmgr.SaveTaBaseValue(row)
	return ctx.JSON(http.StatusOK, "add a new ta base value ok!")
}

func (s *MyRestAPIServer) postTaBValueByMultiForm(ctx echo.Context, id int64, tauuid string) error {
	name := ctx.FormValue(strName)
	//sEnv := ctx.FormValue(strEnabled)
	//enabled, _ := strconv.ParseBool(sEnv)
	//这里的enabled不需要post
	valueinfo, err := s.getFile(ctx, strVInfo)
	if err != nil && err != http.ErrMissingFile {
		return err
	}
	row := &typdefs.TaBaseRow{
		ClientID:   id,
		Uuid:       tauuid,
		CreateTime: time.Now(),
		Name:       name,
		Valueinfo:  []byte(valueinfo),
	}
	trustmgr.DisableTaBaseByUuid(id, tauuid)
	logger.L.Debug(strDisableTaBaseByUuid)

	trustmgr.SaveTaBaseValue(row)
	/* // no use???
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusFound, row)
	}
	*/
	return ctx.Redirect(http.StatusFound, fmt.Sprintf("/%d/ta/%s/tabasevalues", id, tauuid))
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

// GetIdReports get node {id} all reports
//
//	get node {id} all reports as html
//	  curl -X GET http://localhost:40002/{id}/reports
//	get node {id} all reports as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}/reports
//	  curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/reports
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

// DeleteIdReportsReportid delete node {id} one report {reportid}
//
//	delete node {id} report {reportid} by html
//	  curl -X DELETE http://localhost:40002/{id}/reports/{reportid}
//	delete node {id} report {reportid} by json
//	  curl -X DELETE -H "Content-type: application/json" http://localhost:40002/{id}/reports/{reportid}
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

// GetIdReportsReportid get node {id} one report {reportid}
//
//	get node {id} report {reportid} as html
//	  curl -X GET http://localhost:40002/{id}/reports/{reportid}
//	get node {id} report {reportid} as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}/reports/{reportid}
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

// GetIdContainerStatus return a list of trust status for all containers of a given client
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

// GetIdDeviceStatus return a list of trust status for all devices of a given client
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

func genNewTaBaseValueHtml(id int64, tauuid string) string {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(htmlNewTaBaseValue, id, tauuid))
	return buf.String()
}

// (GET /{id}/ta/{tauuid}/newtabasevalue)

// GetIdTaTauuidNewtabasevalue gets ta basevalue.
// curl -k -X GET  -H "Content-type: application/json" https://localhost:40003/30/ta/test/newtabasevalue
// test pass, TODO: HTML implementation
func (s *MyRestAPIServer) GetIdTaTauuidNewtabasevalue(ctx echo.Context, id int64, tauuid string) error {
	return ctx.HTML(http.StatusOK, genNewTaBaseValueHtml(id, tauuid))
}

// (POST /{id}/ta/{tauuid}/newtabasevalue)

// PostIdTaTauuidNewtabasevalue saves node {id} a new base value by json
//	curl -X POST -H "Content-Type: application/json" -k https://localhost:40003/{id}/ta/{tauuid}/newtabasevalue -d '{"name":"testname", "enabled":true, "valueinfo":"test info", "isnewgroup":false}'
//	curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -k https://localhost:40003/24/ta/test/newtabasevalue -d '{"name":"testname", "enabled":true, "valueinfo":"test info", "isnewgroup":false}'
func (s *MyRestAPIServer) PostIdTaTauuidNewtabasevalue(ctx echo.Context, id int64, tauuid string) error {
	if checkJSON(ctx) {
		return s.postTaBValueByJson(ctx, id, tauuid)
	}
	if checkXML(ctx) {
		return s.postTaBValueByXml(ctx, id, tauuid)
	}
	return s.postTaBValueByMultiForm(ctx, id, tauuid)
}

// GetIdTaTauuidStatus returns the trust status for a specific TA of a given client
// (GET /{id}/ta/{tauuid}/status)
// curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/{id}/ta/{tauuid}/status
// test pass
func (s *MyRestAPIServer) GetIdTaTauuidStatus(ctx echo.Context, id int64, tauuid string) error {
	c, err := trustmgr.GetCache(id)
	if err != nil {
		return err
	}
	status := c.GetTaTrusted(tauuid)
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf(strGetTaStatus, tauuid, status))

	return ctx.JSON(http.StatusOK, buf.String())
}

// GetIdTaTauuidTabasevalues returns ta basevalues qureied by tauuid.
// (GET /{id}/ta/{tauuid}/tabasevalues)
// curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/ta/{tauuid}/tabasevalues
// test pass
func (s *MyRestAPIServer) GetIdTaTauuidTabasevalues(ctx echo.Context, id int64, tauuid string) error {
	rows, err := trustmgr.FindTaBaseValuesByUuid(id, tauuid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, rows)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, "")
	//return ctx.HTML(http.StatusOK, genBaseValuesHtml(id, rows))
	//TODO: genTaBaseValuesHtml(id, rows)
}

// DeleteIdTaTauuidTabasevaluesTabasevalueid deletes ta basevalue.
// (DELETE /{id}/ta/{tauuid}/tabasevalues/{tabasevalueid})
// curl -X DELETE -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" -k http://localhost:40003/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}
// test pass
func (s *MyRestAPIServer) DeleteIdTaTauuidTabasevaluesTabasevalueid(
	ctx echo.Context,
	id int64,
	tauuid string,
	tabasevalueid int64) error {
	err := trustmgr.DeleteTaBaseValueByID(tabasevalueid)
	if checkJSON(ctx) {
		res := JsonResult{}
		if err != nil {
			res.Result = fmt.Sprintf(strDeleteTaBaseValueFail, id, tauuid, tabasevalueid, err)
			return ctx.JSON(http.StatusOK, res)
		}
		res.Result = fmt.Sprintf(strDeleteTaBaseValueSuccess, id, tauuid, tabasevalueid)
		return ctx.JSON(http.StatusOK, res)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(strDeleteTaBaseValueSuccess, id, tauuid, tabasevalueid))
}

// GetIdTaTauuidTabasevaluesTabasevalueid gets ta basevalues by ta basevalue id.
// (GET /{id}/ta/{tauuid}/tabasevalues/{tabasevalueid})
// curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/ta/{tauuid}/tabasevalues{tabasevalueid}
// test pass
func (s *MyRestAPIServer) GetIdTaTauuidTabasevaluesTabasevalueid(
	ctx echo.Context,
	id int64,
	tauuid string,
	tabasevalueid int64) error {
	row, err := trustmgr.FindTaBaseValueByID(tabasevalueid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, row)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, "")
	//return ctx.HTML(http.StatusOK, genBaseValueHtml(row))
	//TODO: genTaBaseValuesHtml(row)
}

// PostIdTaTauuidTabasevaluesTabasevalueid modifies ta basevalues by ta basevalue id.
// (POST /{id}/ta/{tauuid}/tabasevalues/{tabasevalueid})
// curl -k -X POST -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN"  https://localhost:40003/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid} --data '{"enabled":true}'
// test pass
func (s *MyRestAPIServer) PostIdTaTauuidTabasevaluesTabasevalueid(
	ctx echo.Context,
	id int64,
	tauuid string,
	tabasevalueid int64) error {
	if checkJSON(ctx) {
		bv := new(tabaseValueJson)
		err := ctx.Bind(bv)
		if err != nil {
			return ctx.JSON(http.StatusNotAcceptable, errParseWrong)
		}
		trustmgr.ModifyTaEnabledByID(tabasevalueid, bv.Enabled)
		return ctx.JSON(
			http.StatusFound,
			fmt.Sprintf(
				"server id:%d, ta id:%s, basevalueid:%d, modify enabled=%t",
				id,
				tauuid,
				tabasevalueid,
				bv.Enabled))
	}
	sEnv := ctx.FormValue(strEnabled)
	enabled, _ := strconv.ParseBool(sEnv)
	trustmgr.ModifyTaEnabledByID(tabasevalueid, enabled)
	return ctx.HTML(http.StatusFound, "")
}

// (GET /{id}/ta/{tauuid}/tareports)

// GetIdTaTauuidTareports gets node {id} all reports as json
//	  curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}/ta/test/tareports
//	  curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/ta/test/tareports
//
// test pass
func (s *MyRestAPIServer) GetIdTaTauuidTareports(ctx echo.Context, id int64, tauuid string) error {
	rows, err := trustmgr.FindTaReportsByUuid(id, tauuid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, rows)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, "")
	//return ctx.HTML(http.StatusOK, genReportsHtml(id, rows))
	//TODO: genTaReportsHtml(id, rows)
}

// (DELETE /{id}/ta/{tauuid}/tareports/{tareportid})

// DeleteIdTaTauuidTareportsTareportid deletes ta report by ta report id.
// curl -X DELETE -H "Content-type: application/json" http://localhost:40002/{id}/ta/{tauuid}/tareports/{tareportid}
// curl -k -X GET -H "Content-type: application/json" https://localhost:40003/28/ta/test/tareports/2
// test pass
func (s *MyRestAPIServer) DeleteIdTaTauuidTareportsTareportid(
	ctx echo.Context,
	id int64,
	tauuid string,
	tareportid int64) error {
	err := trustmgr.DeleteTaReportByID(tareportid)
	if checkJSON(ctx) {
		res := JsonResult{}
		if err != nil {
			res.Result = fmt.Sprintf(strDeleteTaReportFail, id, tauuid, tareportid, err)
			return ctx.JSON(http.StatusOK, res)
		}
		res.Result = fmt.Sprintf(strDeleteTaReportSuccess, id, tauuid, tareportid)
		return ctx.JSON(http.StatusOK, res)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, fmt.Sprintf(strDeleteTaReportSuccess, id, tauuid, tareportid))
}

// GetIdTaTauuidTareportsTareportid gets ta reports according to ta report id.
// (GET /{id}/ta/{tauuid}/tareports/{tareportid})
// curl -k -X GET -H "Content-type: application/json" https://localhost:40003/28/ta/test/tareports/2
// test pass
func (s *MyRestAPIServer) GetIdTaTauuidTareportsTareportid(
	ctx echo.Context,
	id int64,
	tauuid string,
	tareportid int64) error {
	row, err := trustmgr.FindTaReportByID(tareportid)
	if checkJSON(ctx) {
		if err != nil {
			return err
		}
		return ctx.JSON(http.StatusOK, row)
	}
	if err != nil {
		return err
	}
	return ctx.HTML(http.StatusOK, "")
	//return ctx.HTML(http.StatusOK, genReportsHtml(id, rows))
	//TODO: genTaReportsHtml(id, rows)
}
