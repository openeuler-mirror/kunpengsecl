package main

import (
	"gitee.com/openeuler/kunpengsecl/attestation/ras/clientapi"
)

const addrRaHub string = "127.0.0.1:40003"
const addrRas string = "127.0.0.1:40001"

func main() {
	clientapi.StartRaHub(addrRaHub, addrRas)
}
