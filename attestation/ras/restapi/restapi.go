package restapi

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type RasServer struct {
}

// Return a list of all config items in key:value pair format
// (GET /config)
func (s *RasServer) GetConfig(ctx echo.Context) error {
	name := "version"
	value := "0.1.0"
	configs := [...]ConfigItem{{&name, &value}}
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

func createServer() {
	router := echo.New()
	router.Pre(middleware.RemoveTrailingSlash())
	router.Use(middleware.Logger())

	server := NewRasServer()
	RegisterHandlers(router, server)

	router.Logger.Fatal(router.Start("127.0.0.1:40003"))
}

func createClient() {
	c, _ := NewClientWithResponses("http://127.0.0.1:40003")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	name := "version"
	value := "0.1.0"
	body := PostConfigJSONRequestBody{{&name, &value}}
	configResponse, err := c.GetConfigWithResponse(ctx)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(configResponse)
	configResponse1, err1 := c.PostConfigWithResponse(ctx, body)
	if err1 != nil {
		fmt.Println(err1)
	}
	fmt.Println(configResponse1)
}

func Test() {
	fmt.Println("hello, this is restapi!")
	fmt.Println("restapi created server")
	go createServer()
	time.Sleep(time.Duration(5) * time.Second)
	fmt.Println("restapi created client")
	createClient()
}
