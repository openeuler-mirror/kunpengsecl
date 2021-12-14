/*
For test purpose, do the following steps:
1. open two terminal, one to run ras and another to run rac.
2. in terminal A, run command: go run ras/cmd/main.go
3. in terminal B, run command: go run rac/cmd/main.go
*/
package main

import (
	"fmt"
	"os"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/cache"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
	"github.com/spf13/pflag"
)

const (
	rasVersion = "version 0.1.0"
)

type testValidator struct {
}

func (tv *testValidator) Validate(report *entity.Report) error {
	return nil
}

func init() {
	config.InitRasFlags()
}

func handleCommand() {
	if *config.RasVersionFlag {
		fmt.Printf("remote attestation server(ras): %s\n", rasVersion)
		os.Exit(0)
	}
	if *config.RasTokenFlag {
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
	pflag.Parse()
	handleCommand()
	cfg := config.GetDefault(config.ConfServer)
	config.SetupSignalHandler()

	vm, err := verifier.CreateVerifierMgr()
	if err != nil {
		fmt.Println(err)
		return
	}
	cm := cache.CreateCacheMgr(cache.DEFAULTRACNUM, vm)
	trustmgr.SetExtractor(vm)
	trustmgr.SetValidator(vm)

	go clientapi.StartServer(cfg.GetPort(), cm)
	restapi.StartServer(cfg.GetRestPort(), cm)
}
