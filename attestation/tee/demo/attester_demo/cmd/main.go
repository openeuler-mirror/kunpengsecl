// main package for attester
package main

import "gitee.com/openeuler/kunpengsecl/attestation/tee/demo/attester_demo/attestertools"

func main() {
	attestertools.InitFlags()
	attestertools.LoadConfigs()
	attestertools.HandleFlags()

	attestertools.StartAttester()
}
