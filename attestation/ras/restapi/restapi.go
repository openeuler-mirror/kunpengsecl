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
	"fmt"
	"net/http"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"github.com/labstack/echo/v4"
)

const (
	htmlNodes = `<html><head><title>All Information</title></head><body>
<a href="/login">login</a><br/><a href="/config">config</a><br/>
<table border="1"><tr align="center" bgcolor="#00FF00"><th>ID</th>
<th>RegTime</th><th>Online</th><th>Trusted</th><th>Info</th><th>Action</th></tr>`
	htmlNodeInfo = `<tr align="center"><td>%d</td><td>%s</td><td>%v</td>
<td>%v</td><td><a href="">link</a></td><td>Delete</td></tr>`
	htmlNodeEnd = `</table></body></html>`

	htmlConfig = `<html><head><title>Config Setting</title></head><body>
<a href="/">Back</a><br/><table border="1"><form action="/config" method="post">
<tr align="center" bgcolor="#00FF00"><th>Parameter</th><th>Value</th></tr>`
	htmlConfigEdit = `<tr><td>%s</td><td align="center">
<input type="text" name="%s" value="%d"/></td></tr>`
	htmlConfigEnd = `</table><input type="submit" value="Save"/></form></body></html>`

	htmlVersion = `<html><head><title>config</title></head><body>Version: %s</body></html>`

	strHBDuration     = `Heart Beat Duration(s)`
	nameHBDuration    = `hbduration`
	strTrustDuration  = `Trust Report Duration(s)`
	nameTrustDuration = `trustduration`
)

type MyRestAPIServer struct {
}

func StartServer(port string) {
	e := echo.New()
	RegisterHandlers(e, &MyRestAPIServer{})
	logger.L.Sugar().Debug(e.Start(port))
}

func checkJSON(ctx echo.Context) bool {
	cty := ctx.Request().Header.Get(echo.HeaderContentType)
	if cty == echo.MIMEApplicationJSON || cty == echo.MIMEApplicationJSONCharsetUTF8 {
		return true
	}
	return false
}

func genAllNodesHtml(ctx echo.Context, nodes []typdefs.NodeInfo) string {
	var buf bytes.Buffer
	buf.WriteString(htmlNodes)
	for _, n := range nodes {
		buf.WriteString(fmt.Sprintf(htmlNodeInfo,
			n.ID, n.RegTime, n.Online, n.Trusted))
	}
	buf.WriteString(htmlNodeEnd)
	return buf.String()
}

// (GET /)
// get all nodes information
func (s *MyRestAPIServer) Get(ctx echo.Context) error {
	nodes, err := trustmgr.GetAllNodes()
	if checkJSON(ctx) {
		if err != nil {
			logger.L.Sugar().Debugf("get all nodes error: %v\n", err)
			return ctx.JSON(http.StatusNotFound, []typdefs.NodeInfo{})
		}
		return ctx.JSON(http.StatusOK, nodes)
	}
	if err != nil {
		logger.L.Sugar().Debugf("get all nodes error: %v\n", err)
		return ctx.HTML(http.StatusNotFound, "")
	}
	return ctx.HTML(http.StatusOK, genAllNodesHtml(ctx, nodes))
}

// TODO: add more parameters in this struct to export to outside control.
type cfgRecord struct {
	HBDuration    time.Duration `json:"hbduration" form:"hbduration"`
	TrustDuration time.Duration `json:"trustduration" form:"trustduration"`
}

func genConfigJson(ctx echo.Context) *cfgRecord {
	return &cfgRecord{
		HBDuration:    config.GetHBDuration() / time.Second,
		TrustDuration: config.GetTrustDuration() / time.Second,
	}
}

func genConfigHtml(ctx echo.Context) string {
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
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/config
func (s *MyRestAPIServer) GetConfig(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson(ctx))
	}
	return ctx.HTML(http.StatusOK, genConfigHtml(ctx))
}

// (POST /config)
// modify ras server configuration
//  write config as html/form
//    curl -X POST -d "hbduration=20" -d "trustduration=30" http://localhost:40002/config
//  write config as json
//    curl -X POST -H "Content-type: application/json" -d '{"hbduration": 100, "trustduration": 200}' http://localhost:40002/config
// Notice: key name must be enclosed by "" in json format!!!
func (s *MyRestAPIServer) PostConfig(ctx echo.Context) error {
	cfg := new(cfgRecord)
	err := ctx.Bind(cfg)
	if err != nil {
		logger.L.Sugar().Debugf("config bind error: %v\n", err)
		return err
	}
	config.SetHBDuration(cfg.HBDuration * time.Second)
	config.SetTrustDuration(cfg.TrustDuration * time.Second)
	trustmgr.UpdateAllNodes()
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, genConfigJson(ctx))
	}
	return ctx.HTML(http.StatusOK, genConfigHtml(ctx))
}

// (POST /login)
// login/logout ras server as admin
func (s *MyRestAPIServer) PostLogin(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "login...")
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
func (s *MyRestAPIServer) GetFromTo(ctx echo.Context, from int64, to int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	//ctx.Response().Header().Set(echo.HeaderContentType, "text/plain")
	res := fmt.Sprintf(`<a href="http://example.com/">from %d to %d</a>`, from, to)
	return ctx.HTML(http.StatusOK, res)
}

// (DELETE /{id})
// delete node {id}
func (s *MyRestAPIServer) DeleteId(ctx echo.Context, id int64) error {
	res := fmt.Sprintf("delete %d", id)
	return ctx.HTML(http.StatusOK, res)
}

type Node struct {
	RegTime string `json:"regtime" form:"regtime"`
	Online  bool   `json:"online" form:"online"`
	Trusted bool   `json:"trusted" form:"trusted"`
}

func genNodeJson(ctx echo.Context, c *cache.Cache) *Node {
	return &Node{
		RegTime: c.GetRegTime(),
		Online:  c.GetOnline(),
		Trusted: c.GetTrusted(),
	}
}

func genNodeHtml(ctx echo.Context, c *cache.Cache) string {
	var buf bytes.Buffer
	buf.WriteString(`<html><head><title>node</title></head><body>`)
	buf.WriteString(`<a href="/">Up</a><br/>`)
	buf.WriteString(`<table><tr><th>Parameter</th><th>Value</th></tr>`)
	htmlTableData := `<tr><td>%s</td><td>%v</td></tr>`
	buf.WriteString(fmt.Sprintf(htmlTableData, "Register Time", c.GetRegTime()))
	buf.WriteString(fmt.Sprintf(htmlTableData, "Online", c.GetOnline()))
	buf.WriteString(fmt.Sprintf(htmlTableData, "Trusted", c.GetTrusted()))
	buf.WriteString(`</table></body></html>`)
	return buf.String()
}

// (GET /{id})
// get node {id} information
//  read config as html
//    curl -X GET http://localhost:40002/{id}
//  read config as json
//    curl -X GET -H "Content-type: application/json" http://localhost:40002/{id}
func (s *MyRestAPIServer) GetId(ctx echo.Context, id int64) error {
	c, err := trustmgr.GetCache(id)
	if checkJSON(ctx) {
		if err != nil {
			logger.L.Sugar().Debugf("get node infor error: %v\n", err)
			return ctx.JSON(http.StatusNotFound, &Node{})
		}
		return ctx.JSON(http.StatusOK, genNodeJson(ctx, c))
	}
	if err != nil {
		logger.L.Sugar().Debugf("get node infor error: %v\n", err)
		return ctx.JSON(http.StatusNotFound, "")
	}
	return ctx.HTML(http.StatusOK, genNodeHtml(ctx, c))
}

// (POST /{id})
// modify node {id} information
func (s *MyRestAPIServer) PostId(ctx echo.Context, id int64) error {
	res := fmt.Sprintf("change server %d information", id)
	return ctx.HTML(http.StatusOK, res)
}

// (GET /{id}/basevalues)
// get node {id} all base values
func (s *MyRestAPIServer) GetIdBasevalues(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d all base values", id)
	return ctx.HTML(http.StatusOK, res)
}

// (POST /{id}/basevalues)
// add a new base value to node {id}
func (s *MyRestAPIServer) PostIdBasevalues(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("post server %d to add a new base values", id)
	return ctx.HTML(http.StatusOK, res)
}

// (DELETE /{id}/basevalues/{basevalueid})
// delete node {id} one base value {basevalueid}
func (s *MyRestAPIServer) DeleteIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	res := fmt.Sprintf("delete server %d base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

// (GET /{id}/basevalues/{basevalueid})
// get node {id} one base value {basevalueid}
func (s *MyRestAPIServer) GetIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

// (POST /{id}/basevalues/{basevalueid})
// modify node {id} one base value {basevalueid}
func (s *MyRestAPIServer) PostIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("post server %d to modify base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

// (GET /{id}/reports)
// get node {id} all reports
func (s *MyRestAPIServer) GetIdReports(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d all reports", id)
	return ctx.HTML(http.StatusOK, res)
}

// (DELETE /{id}/reports/{reportid})
// delete node {id} one report {reportid}
func (s *MyRestAPIServer) DeleteIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	res := fmt.Sprintf("delete server %d report %d", id, reportid)
	return ctx.HTML(http.StatusOK, res)
}

// (GET /{id}/reports/{reportid})
// get node {id} one report {reportid}
func (s *MyRestAPIServer) GetIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d report %d", id, reportid)
	return ctx.HTML(http.StatusOK, res)
}
