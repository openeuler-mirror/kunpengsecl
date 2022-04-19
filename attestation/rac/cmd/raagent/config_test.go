package main

import (
	"os"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/common/logger"
	"gitee.com/openeuler/kunpengsecl/attestation/rac/ractools"
)

func TestTPM(t *testing.T) {
	logger.L = logger.NewDebugLogger("")
	testMode := true
	tpmConf := createTPMConfig(testMode)
	err := ractools.OpenTPM(!testMode, tpmConf)
	if err != nil {
		t.Errorf("open tpm failed, %s", err)
		os.Exit(1)
	}
	defer ractools.CloseTPM()
	t.Log("ractools.GenerateEKey()")
	err = ractools.GenerateEKey()
	if err != nil {
		t.Errorf("generate EK failed, %s", err)
	}
	t.Log("ractools.GenerateEKey() ok")
	t.Logf("ek: %v\n", ractools.GetEKPub())
}
