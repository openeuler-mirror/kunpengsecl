package ractools

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

//FIXME: nonce is not used in functions
func CreateTrustReport(rw io.ReadWriter, pcrSelection tpm2.PCRSelection, imapath string, nonce, clientid int64,
	clientinfo map[string]string) (report TrustReport, err error) {

	keyHandle, _, _, _, _, _, err := tpm2.CreatePrimaryEx(rw, tpm2.HandleEndorsement,
		pcrSelection, EmptyPassword, EmptyPassword, Params)
	if err != nil {
		return TrustReport{}, err
	}

	pcrmp, _ := tpm2.ReadPCRs(rw, pcrSelection)
	if err != nil {
		return TrustReport{}, err
	}

	var pcrValues []PcrValue
	for _, pcr := range pcrmp {
		pcrValues = append(pcrValues, (PcrValue)(pcr))
	}

	qattestation, _, err := tpm2.Quote(rw, keyHandle, EmptyPassword, EmptyPassword,
		nil, pcrSelection, tpm2.AlgNull)
	if err != nil {
		return TrustReport{}, err
	}

	var pcrinfo PcrInfo = PcrInfo{pcrSelection, pcrValues, qattestation}

	//To construct the manifest
	f, err := ioutil.ReadFile(imapath)
	if err != nil {
		return TrustReport{}, err
	}
	var mainfest []Manifest
	s := make([]string, 5, 6)
	var j int = 0
	for i, _ := range f {
		if f[i] == ' ' {
			j++
			continue
		} else if f[i] == '\n' || f[i] == '\t' {
			continue
		}
		s[j] = s[j] + (string)(f[i])
	}
	ma := Manifest{s[0], s[1], s[2], s[3], s[4]}
	mainfest = append(mainfest, ma)

	clientId := clientid
	clientInfo := clientinfo

	var trust_report TrustReport = TrustReport{pcrinfo, mainfest, clientId, clientInfo}

	return trust_report, err
}

func CreateAk(rw io.ReadWriter, parentHandle tpmutil.Handle, parentPassword string) ([]byte, []byte, []byte, error) {

	privateAk, publicAk, _, _, _, err := tpm2.CreateKey(rw, parentHandle, PcrSelection7,
		parentPassword, EmptyPassword, DefaultKeyParams)
	if err != nil {
		return nil, nil, nil, err
	}

	keyHandle, nameData, err := tpm2.Load(rw, parentHandle, parentPassword, publicAk,
		privateAk)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tpm2.FlushContext(rw, keyHandle)

	if _, err := tpm2.DecodeName(bytes.NewBuffer(nameData)); err != nil {
		return nil, nil, nil, err
	}
	_, Akname, _, err := tpm2.ReadPublic(rw, keyHandle)
	if err != nil {
		return nil, nil, nil, err
	}

	return Akname, privateAk, publicAk, nil
}

func ActivateAC(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string,
	credServer, encryptedSecret []byte, secret []byte) (rerecoveredCredential []byte, err error) {

	recoveredCredential, err := tpm2.ActivateCredential(rw, activeHandle, keyHandle, activePassword,
		protectorPassword, credServer, encryptedSecret)
	if err != nil {
		fmt.Printf("ActivateCredential failed: %v \n", err)
	}
	return recoveredCredential, err
}
