// main package for attester
package main

import "gitee.com/openeuler/kunpengsecl/attestation/demo/attester_demo/attestertools"

func main() {
	attestertools.InitFlags()
	attestertools.HandleFlags()

	attestertools.StartAttester()
}
