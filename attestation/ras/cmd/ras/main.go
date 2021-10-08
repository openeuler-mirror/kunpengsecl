package main

import (
	"fmt"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/restapi"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/verifier"
)

func main() {
	fmt.Println("hello, this is ras!")
	clientapi.Test()
	pca.Test()
	restapi.Test()
	trustmgr.Test()
	verifier.Test()
}
