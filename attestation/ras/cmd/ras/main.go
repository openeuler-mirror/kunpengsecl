/*
For test purpose, do the following steps:
1. open two terminal, one to run ras and another to run rac.
2. in terminal A, run command: go run ras/cmd/main.go
3. in terminal B, run command: go run rac/cmd/main.go
*/
package main

import (
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi"
)

func main() {
	// TODO:
	// add argv handling code for parameters
	// or read config from yaml file...
	const addrcapi string = "127.0.0.1:40001"
	const addrrapi string = "127.0.0.1:40002"
	go clientapi.StartServer(addrcapi)
	restapi.StartServer(addrrapi)
}
