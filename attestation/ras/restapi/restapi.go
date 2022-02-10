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
	"fmt"
	"net/http"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"github.com/labstack/echo/v4"
)

type MyServer struct {
}

func StartServer(port string) {
	e := echo.New()
	RegisterHandlers(e, &MyServer{})
	logger.L.Sugar().Debug(e.Start(port))
}

func checkJSON(ctx echo.Context) bool {
	cty := ctx.Request().Header.Get(echo.HeaderContentType)
	if cty == echo.MIMEApplicationJSON || cty == echo.MIMEApplicationJSONCharsetUTF8 {
		return true
	}
	return false
}

func (s *MyServer) Get(ctx echo.Context) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	//ctx.Response().Header().Set(echo.HeaderContentType, "text/plain")
	return ctx.HTML(http.StatusOK, `<a href="http://example.com/">show all server information</a>`)
}

func (s *MyServer) GetConfig(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "current configuration")
}

func (s *MyServer) PostConfig(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "save new configuration")
}

func (s *MyServer) PostLogin(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "login...")
}

func (s *MyServer) GetVersion(ctx echo.Context) error {
	return ctx.HTML(http.StatusOK, "version 1.0.0")
}

func (s *MyServer) GetFromTo(ctx echo.Context, from int64, to int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	//ctx.Response().Header().Set(echo.HeaderContentType, "text/plain")
	res := fmt.Sprintf(`<a href="http://example.com/">from %d to %d</a>`, from, to)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) DeleteId(ctx echo.Context, id int64) error {
	res := fmt.Sprintf("delete %d", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) GetId(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d all information", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) PostId(ctx echo.Context, id int64) error {
	res := fmt.Sprintf("change server %d information", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) GetIdBasevalues(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d all base values", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) PostIdBasevalues(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("post server %d to add a new base values", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) DeleteIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	res := fmt.Sprintf("delete server %d base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) GetIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) PostIdBasevaluesBasevalueid(ctx echo.Context, id int64, basevalueid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("post server %d to modify base value %d", id, basevalueid)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) GetIdReports(ctx echo.Context, id int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d all reports", id)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) DeleteIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	res := fmt.Sprintf("delete server %d report %d", id, reportid)
	return ctx.HTML(http.StatusOK, res)
}

func (s *MyServer) GetIdReportsReportid(ctx echo.Context, id int64, reportid int64) error {
	if checkJSON(ctx) {
		return ctx.JSON(http.StatusOK, s)
	}
	res := fmt.Sprintf("get server %d report %d", id, reportid)
	return ctx.HTML(http.StatusOK, res)
}
