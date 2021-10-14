package ractools

import (
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
	pcrSelection = PcrSelection7
	tpmPath      = flag.String("tpm-path", "", `Path to TPM character device. Most Linux systems 
	expose it under /dev/tpm0. Empty value (default) will disable all integration tests.`)
)

func openTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	if useDeviceTPM() {
		return openDeviceTPM(tb)
	}
	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	return simulator
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
	rw := openTPM(t)
	defer rw.Close()

	var (
		imaInfo = `10 1d8d532d463c9f8c205d0df7787669a85f93e260 ima-ng 
		sha1:0000000000000000000000000000000000000000 boot_aggregate`
		imapath          = "imapath"
		nonce      int64 = 1
		clientId   int64 = 1
		clientInfo map[string]string
	)
	clientInfo = make(map[string]string)
	clientInfo["version"] = "0.0.1"

	ioutil.WriteFile(imapath, ([]byte)(imaInfo), 0777)
	_, err := CreateTrustReport(rw, pcrSelection, imapath, nonce, clientId, clientInfo)
	if err != nil {
		t.Fatalf("CreateTrustReport failed: %s", err)
	}

}

func TestCreateAk(t *testing.T) {
	rw := openTPM(t)
	defer rw.Close()

	ownerPassword := EmptyPassword
	parentPassword := MyPassword
	parentHandle, _, err := tpm2.CreatePrimary(rw, HandleOwner, pcrSelection,
		ownerPassword, parentPassword, DefaultKeyParams)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	_, _, _, err = CreateAk(rw, parentHandle, parentPassword)
	if err != nil {
		t.Fatalf("CreateAk failed: %s", err)
	}
}
