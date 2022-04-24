package main

import "gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"

func main() {
	qcatools.LoadConfigs()
	qcatools.StartServer()
}
