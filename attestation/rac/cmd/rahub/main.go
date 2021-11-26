package main

import (
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"github.com/spf13/pflag"
)

func init() {
	config.InitHubFlags()
}

func main() {
	pflag.Parse()
	cfg := config.GetDefault()
	rasServer := cfg.GetHubServer()
	listenPort := cfg.GetHubPort()
	clientapi.StartRaHub(listenPort, rasServer)
}
