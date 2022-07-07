/***
Description: main package for ak service
***/

package main

import (
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
)

func main() {
	config.LoadConfigs()
	err := config.InitializeAS()
	if err != nil {
		log.Print(err)
	}
	server := config.GetServerPort()
	clientapi.StartServer(server)
}
