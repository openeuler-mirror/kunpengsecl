package main

import (
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_daemon/daemontools"
)

func main() {
	daemontools.InitFlags()
	info, err := daemontools.GetVirtualClientInfo()
	if err != nil {
		log.Fatalf("get virtual os info failed, %v", err)
	}
	daemontools.StartClientConn(*daemontools.HostServer, info)
}
