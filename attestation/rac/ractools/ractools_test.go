package ractools

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner tpmutil.Handle = 0x40000001
)

var (
	pcrSelection        = pcrSelection0to7
	nonce        uint64 = 1
	clientId     int64  = 1
	ekDer               = ([]byte)(`0��0��0
		*�H��
	`)
)

func TestCreateTrustReport(t *testing.T) {
	tpm, err := OpenTPM(false)
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
	tpm.Prepare(&TPMConfig{})
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
	got, err := tpm.createTrustReport(pcrSelection, &tRepIn)
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

	attestation, _, err := tpm2.Quote(tpm.dev, tpmutil.Handle(tpm.config.IK.Handle), tpm.config.IK.Password, emptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		t.Fatalf("Quote failed: %s", err)
	}
	_, err = tpm2.DecodeAttestationData(attestation)
	if err != nil {
		t.Fatalf("DecodeAttestationData failed: %s", err)
	}
}

func TestNVRAM(t *testing.T) {
	tpm, err := OpenTPM(false)
	if err != nil {
		t.Errorf("OpenTPM failed, err: %v", err)
		return
	}
	defer tpm.Close()

	// use this will have "error code 0xb : the handle is not correct for the use"
	tpm.EraseEKCert()
	tpm.WriteEKCert(ekDer)
	ekCert, err := tpm.ReadEKCert()
	if err != nil {
		t.Errorf("ReadEKCert failed, err: %v", err)
	}
	if !bytes.Equal(ekCert, []byte(ekDer)) {
		t.Errorf("EKCert are not equal, \n got: %v, \n want: %v \n", ekCert, ekDer)
	}
	tpm.EraseEKCert()
}
