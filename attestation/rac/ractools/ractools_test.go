package ractools

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner tpmutil.Handle = 0x40000001
)

var (
	pcrSelection        = pcrSelection0to7
	nonce        uint64 = 1
	clientId     int64  = 1
	testMode            = false
)

/*
func TestCreateTrustReport(t *testing.T) {
	tpmConf := TPMConfig{}
	tpmConf.IMALogPath = TestImaLogPath
	tpmConf.BIOSLogPath = TestBiosLogPath
	tpmConf.ReportHashAlg = ""
	tpm, err := OpenTPM(testMode, &tpmConf)
	if err != nil {
		t.Errorf("OpenTPM failed, err: %v", err)
		return
	}
	defer tpm.Close()

	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientId,
		ClientInfo: "",
	}

	//create EK,Ak,TrustReport
	got, err := tpm.createTrustReport(testMode, pcrSelection, &tRepIn)
	if err != nil {
		t.Fatalf("CreateTrustReport failed: %s", err)
	}

	//compare pcrInfo
	pcrmp, _ := tpm2.ReadPCRs(tpm.dev, pcrSelection)
	pcrValues := map[int]string{}
	for key, pcr := range pcrmp {
		pcrValues[key] = hex.EncodeToString(pcr)
	}
	for i := range pcrmp {
		if got.PcrInfo.Values[int32(i)] != pcrValues[i] {
			t.Fatalf("PCRs are not equal, got %v want %v", []byte(got.PcrInfo.Values[(int32)(i)]), pcrValues[i])
		}
	}

	attestation, _, err := tpm2.Quote(tpm.dev, tpm.IK.Handle, tpm.IK.Password, emptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		t.Fatalf("Quote failed: %s", err)
	}
	_, err = tpm2.DecodeAttestationData(attestation)
	if err != nil {
		t.Fatalf("DecodeAttestationData failed: %s", err)
	}
}
*/
func TestNVRAM(t *testing.T) {
	var testNVIndex uint32 = 0x01C00030
	tpmConf := TPMConfig{}
	tpmConf.IMALogPath = TestImaLogPath
	tpmConf.BIOSLogPath = TestBiosLogPath
	tpmConf.ReportHashAlg = ""
	tpm, err := OpenTPM(testMode, &tpmConf)
	if err != nil {
		t.Errorf("OpenTPM failed, err: %v", err)
		return
	}
	defer tpm.Close()

	priv, _ := rsa.GenerateKey(rand.Reader, pca.RsaKeySize)
	// sign by root ca
	ekDer, err := x509.CreateCertificate(rand.Reader, &pca.RootTemplate, &pca.RootTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Errorf("CreateCertificate failed, err: %v", err)
	}

	tpm.UndefineNVRAM(testNVIndex)
	tpm.DefineNVRAM(testNVIndex, uint16(len(ekDer)))
	tpm.WriteNVRAM(testNVIndex, ekDer)
	ekCert, err := tpm.ReadNVRAM(testNVIndex)
	if err != nil {
		t.Errorf("ReadEKCert failed, err: %v", err)
	}
	if !bytes.Equal(ekCert, ekDer) {
		t.Errorf("EKCert are not equal, got: %v, want: %v \n", ekCert, ekDer)
	}
	tpm.UndefineNVRAM(testNVIndex)
}
