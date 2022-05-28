package main

import (
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

func main() {
	qcatools.InitFlags()
	qcatools.LoadConfigs()
	qcatools.HandleFlags()

	qapi.StartServer()
}
