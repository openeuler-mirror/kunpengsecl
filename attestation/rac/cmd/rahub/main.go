package main

import (
	"fmt"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"github.com/spf13/pflag"
)

const (
	rahubVersion = "version 0.1.0"
)

func init() {
	config.InitHubFlags()
}

func main() {
	pflag.Parse()
	if *config.HubVersionFlag {
		fmt.Printf("remote attestation hub(rahub): %s\n", rahubVersion)
		return
	}
	cfg := config.GetDefault(config.ConfHub)
	rasServer := cfg.GetHubServer()
	listenPort := cfg.GetHubPort()
	clientapi.StartRaHub(listenPort, rasServer)
}
