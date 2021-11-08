package ractools

import (
	"bytes"
	"flag"
	"io"
	"io/ioutil"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner tpmutil.Handle = 0x40000001
)

var (
	tpmPath = flag.String("tpm-path", "", `Path to TPM character device. Most Linux systems 
	expose it under /dev/tpm0. Empty value (default) will disable all integration tests.`)
	pcrSelection = PcrSelection7
	imaTestInfo  = `10 1d8d532d463c9f8c205d0df7787669a85f93e260 ima-ng 
		sha1:0000000000000000000000000000000000000000 boot_aggregate`
	imaInfo = `10 1d8d532d463c9f8c205d0df7787669a85f93e260 ima-ng 
		sha1:0000000000000000000000000000000000000000 boot_aggregate`
	imaTestPath        = "imaTestPath"
	imaPath            = "imapath"
	nonce       uint64 = 1
	clientId    int64  = 1
	//TPM simulator PCRDigest
	PCRDigestS []byte = []byte{222, 71, 201, 178, 126, 184, 211, 0, 219, 181,
		242, 195, 83, 230, 50, 195, 147, 38, 44, 240, 99, 64, 196, 250, 127, 27, 64, 196, 203, 211, 111, 144}
	//Physical TPM PCRDigest
	PCRDigestP []byte = []byte{60, 13, 233, 2, 198, 16, 14, 200, 249, 63, 3,
		95, 211, 74, 220, 203, 79, 247, 227, 31, 126, 184, 41, 19, 100, 35, 51, 36, 128, 209, 90, 2}
	PCRDigest      []byte
	parentPassword = EmptyPassword
	ownerPassword  = EmptyPassword
)

//if open physical TPM, return true, else return false
func openTPM(tb testing.TB) (io.ReadWriteCloser, bool) {
	tb.Helper()
	if useDeviceTPM() {
		return openDeviceTPM(tb), true
	}
	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	return simulator, false
}

func useDeviceTPM() bool { return *tpmPath != "" }

func openDeviceTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		tb.Fatalf("Open TPM at %s failed: %s\n", *tpmPath, err)
	}
	return rw
}

func TestCreateTrustReport(t *testing.T) {
	if tpm.dev == nil {
		tpm.dev, isPhysicalTpm = openTPM(t)
		//defer tpm.dev.Close()
	}

	if isPhysicalTpm {
		PCRDigest = PCRDigestP
	} else {
		PCRDigest = PCRDigestS
	}

	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientId,
		ClientInfo: "",
	}
	//generate ima-testfile
	ioutil.WriteFile(imaTestPath, ([]byte)(imaTestInfo), 0777)
	ioutil.WriteFile(imaPath, ([]byte)(imaInfo), 0777)

	//create EK,Ak,TrustReport
	AK, _, err := GetAk()
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
	got, err := CreateTrustReport(tpm.dev, AK, pcrSelection, tRepIn)
	if err != nil {
		t.Fatalf("CreateTrustReport failed: %s", err)
	}

	//compare pcrInfo
	pcrmp, _ := tpm2.ReadPCRs(tpm.dev, pcrSelection)
	pcrValues := map[int]string{}
	for key, pcr := range pcrmp {
		var value string
		for _, c := range pcr {
			value += (string)(c + 48) //invert byte(0) into string(0)
		}
		pcrValues[key] = value
	}
	for i, _ := range pcrmp {
		if got.PcrInfo.Values[i] != pcrValues[i] {
			t.Fatalf("PCRs are not equal, got %v want %v", []byte(got.PcrInfo.Values[i]), pcrValues[i])
		}
	}

	attestation, _, err := tpm2.Quote(tpm.dev, AK.Handle, AK.Password, EmptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		t.Fatalf("Quote failed: %s", err)
	}
	decoded, err := tpm2.DecodeAttestationData(attestation)
	if err != nil {
		t.Fatalf("DecodeAttestationData failed: %s", err)
	}
	if !bytes.Equal(decoded.AttestedQuoteInfo.PCRDigest, PCRDigest) {
		t.Fatalf("PCRDigest are not equal, got %v want %v", decoded.AttestedQuoteInfo.PCRDigest, PCRDigest)
	}

}

func TestCreateAk(t *testing.T) {
	if tpm.dev == nil {
		tpm.dev, isPhysicalTpm = openTPM(t)
		//defer tpm.dev.Close()
	}

	parentHandle, _, err := tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, pcrSelection,
		ownerPassword, parentPassword, DefaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(tpm.dev, parentHandle)

	_, _, _, err = CreateAk(tpm.dev, parentHandle, parentPassword, EmptyPassword, MyPcrSelection)
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
}

func TestGetAk(t *testing.T) {
	_, _, err := GetAk()
	if err != nil {
		t.Fatalf("GetAk failed: %s", err)
	}
}

func TestGetTrustReport(t *testing.T) {
	_, err := GetTrustReport(TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientId,
		ClientInfo: "",
	})
	if err != nil {
		t.Fatalf("GetAk failed: %s", err)
	}
}
