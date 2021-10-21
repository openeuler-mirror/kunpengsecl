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
	imaTestPath       = "imaTestPath"
	imaPath           = "imapath"
	nonce       int64 = 1
	clientId    int64 = 1
	clientInfo  map[string]string
	//TPM simulator PCRDigest
	PCRDigestS []byte = []byte{222, 71, 201, 178, 126, 184, 211, 0, 219, 181,
		242, 195, 83, 230, 50, 195, 147, 38, 44, 240, 99, 64, 196, 250, 127, 27, 64, 196, 203, 211, 111, 144}
	//Physical TPM PCRDigest
	PCRDigestP []byte = []byte{60, 13, 233, 2, 198, 16, 14, 200, 249, 63, 3,
		95, 211, 74, 220, 203, 79, 247, 227, 31, 126, 184, 41, 19, 100, 35, 51, 36, 128, 209, 90, 2}
	PCRDigest      []byte
	parentPassword = MyPassword
	ownerPassword  = EmptyPassword
	AkPassword     = MyPassword
	AkSel          = PcrSelection1_17
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

func compareManifest(t *testing.T, got, want []Manifest) {
	if len(got) != len(want) {
		t.Fatalf("Manifests are not equal in length")
	}
	for i, _ := range got {
		if got[i].pcr != want[i].pcr {
			t.Fatalf("Manifests are not equal, got %v want %v", got[i].pcr, want[i].pcr)
		}
		if got[i].template_hash != want[i].template_hash {
			t.Fatalf("Manifests are not equal, got %v want %v", got[i].template_hash, want[i].template_hash)
		}
		if got[i].format != want[i].format {
			t.Fatalf("Manifests are not equal, got %v want %v", got[i].format, want[i].format)
		}
		if got[i].filedata_hash != want[i].filedata_hash {
			t.Fatalf("Manifests are not equal, got %v want %v", got[i].filedata_hash, want[i].filedata_hash)
		}
		if got[i].filename_hint != want[i].filename_hint {
			t.Fatalf("Manifests are not equal, got %v want %v", got[i].filename_hint, want[i].filename_hint)
		}
	}
}
func TestCreateTrustReport(t *testing.T) {
	rw, isPhysiacl := openTPM(t)
	defer rw.Close()

	if isPhysiacl {
		PCRDigest = PCRDigestP
	} else {
		PCRDigest = PCRDigestS
	}
	clientInfo = make(map[string]string)
	clientInfo["version"] = "0.0.1"

	//generate ima-testfile
	ioutil.WriteFile(imaTestPath, ([]byte)(imaTestInfo), 0777)
	ioutil.WriteFile(imaPath, ([]byte)(imaInfo), 0777)

	//create EK,Ak,TrustReport
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, PcrSelection7, ownerPassword, parentPassword, DefaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	_, privateAk, publicAk, err := CreateAk(rw, parentHandle, parentPassword, AkPassword, AkSel)
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
	AkHandle, _, err := tpm2.Load(rw, parentHandle, parentPassword, publicAk, privateAk)
	if err != nil {
		t.Fatalf("LoadAk failed: %s", err)
	}
	got, err := CreateTrustReport(rw, AkHandle, AkPassword, pcrSelection, imaPath, nonce, clientId, clientInfo)
	if err != nil {
		t.Fatalf("CreateTrustReport failed: %s", err)
	}

	//compare pcrInfo
	pcrmp, _ := tpm2.ReadPCRs(rw, pcrSelection)

	i := 0
	for _, pcr := range pcrmp {
		if !bytes.Equal(pcr, []byte(got.pcrInfo.pcrValues[i])) {
			t.Fatalf("PCRs are not equal, got %v want %v", []byte(got.pcrInfo.pcrValues[i]), pcr)
		}
		i += 1
	}

	attestation, _, err := tpm2.Quote(rw, AkHandle, AkPassword, EmptyPassword,
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

	//compare manifest
	testManifest, err := GetManifest(imaTestPath)
	if err != nil {
		t.Fatalf("GetManifest failed: %s", err)
	}
	compareManifest(t, got.manifest, testManifest)
}

func TestCreateAk(t *testing.T) {
	rw, _ := openTPM(t)
	defer rw.Close()

	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, pcrSelection,
		ownerPassword, parentPassword, DefaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	_, _, _, err = CreateAk(rw, parentHandle, parentPassword, AkPassword, AkSel)
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
}
