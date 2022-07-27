/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2021-09-17
Description: main package for ras.
	1. 2022-01-17	wucaijun
		reorg the ras, use common directory for normal funtions.
*/

// main package entry for remote attestation server.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi"
)

// signalHandler handles the singal and save configurations.
func signalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		clientapi.StopServer()
		config.SaveConfigs()
		os.Exit(0)
	}()
}

// handleGlobalFlags handles the global flags that should do something outside the config package.
func handleGlobalFlags() {
	if config.VersionFlag != nil && *config.VersionFlag {
		fmt.Printf("remote attestation server(ras): %s\n", config.RasVersion)
		os.Exit(0)
	}
	if config.TokenFlag != nil && *config.TokenFlag {
		token, err := restapi.CreateTestAuthToken()
		if err != nil {
			fmt.Printf("create test auth token failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("please pass below line as a whole in http Authorization header:\nBearer %s\n", string(token))
		os.Exit(0)
	}
}

func main() {
	//path, _ := os.Getwd() // only for test when runing under "kunpengsecl/attestation/ras/cmd/ras".
	fileName, _ := os.Executable()
	fmt.Printf("exec: %s, %d\n", fileName, os.Getpid())

	config.InitFlags()
	config.LoadConfigs()
	config.HandleFlags()
	handleGlobalFlags()
	signalHandler()

	logger.L.Debug("start server")
	go restapi.StartServer(config.GetHttpsSwitch())
	clientapi.StartServer(config.GetServerPort())
}
