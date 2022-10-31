// Description: main package for ak service

package main

import (
	"fmt"
	"log"
	"os"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
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
	clientapi.StartServer(config.GetServerPort())
}
