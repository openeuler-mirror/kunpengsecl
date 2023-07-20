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
Create: 2022-04-01
Description: main package for ak service
*/

package main

import (
	"fmt"
	"log"
	"os"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi/server"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/restapi"
)

// handleGlobalFlags handles the global flags that should do something outside the config package.
func handleGlobalFlags() {
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
	config.InitFlags()
	config.LoadConfigs()
	err := config.InitializeAS()
	if err != nil {
		log.Print(err)
	}
	handleGlobalFlags()
	go restapi.StartServer(config.GetRestPort())
	server.StartServer(config.GetServerPort())
}
