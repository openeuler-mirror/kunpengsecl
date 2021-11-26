package ractools

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	HandleOwner tpmutil.Handle = 0x40000001
)

var (
	pcrSelection        = PcrSelection0to7
	nonce        uint64 = 1
	clientId     int64  = 1
	ekPem               = `
-----BEGIN CERTIFICATE-----
MIIEUjCCAjqgAwIBAgIUTPeuiawsSuv0Gs0oAuf/vbRzzYIwDQYJKoZIhvcNAQEL
BQAwVTELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJheWVybjERMA8GA1UEBwwITXVl
bmNoZW4xFTATBgNVBAoMDE9yZ2FuaXphdGlvbjELMAkGA1UEAwwCQ0EwHhcNMjEx
MTExMTE1NTQ4WhcNNDExMTA4MTE1NTQ4WjBdMQswCQYDVQQGEwJERTEPMA0GA1UE
CAwGQmF5ZXJuMREwDwYDVQQHDAhNdWVuY2hlbjEVMBMGA1UECgwMT3JnYW5pemF0
aW9uMRMwEQYDVQQDDApJQk0gU1cgVFBNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAzrGnWHhXFHU4A0XZSjsoE28i0ZiKJ+tyiH8vIhDaD5QYrLTy/pPr
AK7EE3iQ5pY3h5NiGfAnEdFGOx95U9rC3bwIRUat/gqAwjLYReRcN64TshrzbL8t
mmzUErfOKuBk6Sfy4A9qTnh9J1sNH5hYSAViYJbUQfvYyjGKVNEd9FN6mJS6iSs8
iacIj5gcYiUVnGGj9SC4RhknSQfWtbKgfFwN5Ja79s0xy55j1XG7gIn36OD/w9Tc
5mPcQarG3d8spRClcBUXqd7JCub5OmY9fSbBgaiJGjKsS39kz0+A8Y6DW+/LK9+8
DG2PNY32yLKm3eT0KJiq4ecW1MhSQ+ZH6wIDAQABoxIwEDAOBgNVHQ8BAf8EBAMC
BSAwDQYJKoZIhvcNAQELBQADggIBALLSDDghf6dFEvnet1GhO8mtCXkS12UA6eI6
8CM+D/7Q72eez2bUbVIG30F9JFVYlAF3PFG4A2F2cHfmR8JH3LrwCsuf1kqtFgFB
tjNHtawyJHoKNaWEPRLfEvwp5fIhWIc7bEkbqzDIErKXAfTpOaJSAHTFpNUuoe6x
CUs/xfpNIuhNFWX0hMALHnWQX9tsiyr6q3/WjPucovjvFQv9c9djckdGVohzHCuB
W1XrpS1LlTZnoOIrHpDYOkkIkdAGR4Qeyqi+mGovcvkf9/QQsk2MSovGjBiROQ9a
zpa3mhiKdCjbvABxRtI94QBeJ0zMRvQXuDIGd2WIgkFqp8tjC7guUx4uSvwlxxO6
DtFykLOvb09zJzcyPqzk5HnG8Lp7HGY2/tTcltjs7JNILxL35jIs0hIURAtM0e9r
jJyPeuwDcIeYyrohq6FoAPa/z7yK75swWyzCoiisdxOnIUd5V04x5WCl6417kIJ5
EPy4v6zH4STVyt010PwL1yJFCEDQgoSVepbKwm9xpPJHC/cV1Y+Jo+Y/ubJjTiwf
AEwaHvFqEGmkBVK/dGGJmhSo3h8ohapduWXkLiNI041An5rpTwbwoUF+sxrzn9WC
UIp9on4e9ggL7OA2BrfRcfIfyK6LQ+UvnFpufY3hfDxoUuhyvnANfGnbo7d16H1n
j0wy1+Fw
-----END CERTIFICATE-----`
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
	got, err := tpm.createTrustReport(tpm.config.IK, pcrSelection, tRepIn)
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
	for i := range pcrmp {
		if got.PcrInfo.Values[(int32)(i)] != pcrValues[i] {
			t.Fatalf("PCRs are not equal, got %v want %v", []byte(got.PcrInfo.Values[(int32)(i)]), pcrValues[i])
		}
	}

	attestation, _, err := tpm2.Quote(tpm.dev, tpm.config.IK.Handle, tpm.config.IK.Password, EmptyPassword,
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
	tpm.WriteEKCert([]byte(ekPem))
	ekCert, err := tpm.ReadEKCert()
	if err != nil {
		t.Errorf("ReadEKCert failed, err: %v", err)
	}
	if !bytes.Equal(ekCert, []byte(ekPem)) {
		t.Errorf("EKCert are not equal, got: %v, want: %v \n", ekCert, ekPem)
	}
	tpm.EraseEKCert()
}

