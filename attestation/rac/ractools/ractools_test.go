package ractools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner     tpmutil.Handle = 0x40000001
	testImaLogPath                 = "../cmd/raagent/ascii_runtime_measurements"
	testBiosLogPath                = "../cmd/raagent/binary_bios_measurements"
)

var (
	pcrSelection        = pcrSelectionAll
	nonce        uint64 = 1
	clientId     int64  = 1
	testMode            = false
)

func TestCreateTrustReport(t *testing.T) {
	TpmConf := TPMConfig{}
	TpmConf.IMALogPath = testImaLogPath
	TpmConf.BIOSLogPath = testBiosLogPath
	TpmConf.ReportHashAlg = ""
	Tpm, err := OpenTPM(testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()

	clientInfo, err := GetClientInfo(testMode)
	if err != nil {
		t.Errorf("GetClientInfo failed: %s", err)
	}
	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientId,
		ClientInfo: clientInfo,
	}

	//create EK,Ak,TrustReport
	err = Tpm.GenerateEKey()
	if err != nil {
		t.Errorf("Create Ek failed: %s", err)
	}
	err = Tpm.GenerateIKey()
	if err != nil {
		t.Errorf("Create Ik failed: %s", err)
	}
	got, err := Tpm.createTrustReport(testMode, pcrSelection, &tRepIn)
	if err != nil {
		t.Errorf("CreateTrustReport failed: %s", err)
	}

	//compare pcrInfo
	pcrmp, _ := Tpm.readPcrs(pcrSelection)
	pcrValues := map[int]string{}
	for key, pcr := range pcrmp {
		pcrValues[key] = hex.EncodeToString(pcr)
	}
	for i := range pcrmp {
		if got.PcrInfo.Values[int32(i)] != pcrValues[i] {
			t.Errorf("PCRs are not equal, got %v want %v", []byte(got.PcrInfo.Values[(int32)(i)]), pcrValues[i])
		}
	}

	attestation, _, err := tpm2.Quote(Tpm.dev, Tpm.IK.Handle, Tpm.IK.Password, emptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		t.Errorf("Quote failed: %s", err)
	}
	_, err = tpm2.DecodeAttestationData(attestation)
	if err != nil {
		t.Errorf("DecodeAttestationData failed: %s", err)
	}
}

func TestNVRAM(t *testing.T) {
	var testNVIndex uint32 = 0x01C00030
	TpmConf := TPMConfig{}
	TpmConf.IMALogPath = TestImaLogPath
	TpmConf.BIOSLogPath = TestBiosLogPath
	TpmConf.ReportHashAlg = ""
	Tpm, err := OpenTPM(testMode, &TpmConf)
	if err != nil {
		t.Errorf("OpenTpm failed, err: %v", err)
		return
	}
	defer Tpm.Close()

	priv, _ := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
	// sign by root ca
	ekDer, err := x509.CreateCertificate(rand.Reader, &pca.RootTemplate, &pca.RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("CreateCertificate failed, err: %v", err)
	}

	Tpm.UndefineNVRAM(testNVIndex)
	Tpm.DefineNVRAM(testNVIndex, uint16(len(ekDer)))
	Tpm.WriteNVRAM(testNVIndex, ekDer)
	ekCert, err := Tpm.ReadNVRAM(testNVIndex)
	if err != nil {
		t.Errorf("ReadEKCert failed, err: %v", err)
	}
	if !bytes.Equal(ekCert, ekDer) {
		t.Errorf("EKCert are not equal, got: %v, want: %v \n", ekCert, ekDer)
	}
	Tpm.UndefineNVRAM(testNVIndex)
}
