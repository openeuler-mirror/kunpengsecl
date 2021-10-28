package ractools

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	TRep  *TrustReport
	AK    *AttestionKey
	EkPub crypto.PublicKey
)

func GetManifest(imapath string) ([]Manifest, error) {
	f, err := ioutil.ReadFile(imapath)
	if err != nil {
		return nil, err
	}
	var manifest []Manifest
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
	manifest = append(manifest, ma)
	return manifest, nil
}

func CreateAk(rw io.ReadWriter, parentHandle tpmutil.Handle, parentPassword, AkPassword string,
	AkSel tpm2.PCRSelection) ([]byte, []byte, []byte, error) {

	privateAk, publicAk, _, _, _, err := tpm2.CreateKey(rw, parentHandle, AkSel,
		parentPassword, AkPassword, Params)
	if err != nil {
		return nil, nil, nil, err
	}

	akHandle, _, err := tpm2.Load(rw, parentHandle, parentPassword, publicAk,
		privateAk)
	if err != nil {
		return nil, nil, nil, err
	}

	_, akname, _, err := tpm2.ReadPublic(rw, akHandle)
	if err != nil {
		return nil, nil, nil, err
	}

	return akname, privateAk, publicAk, nil
}

func CreateTrustReport(rw io.ReadWriter, AK *AttestionKey, pcrSelection tpm2.PCRSelection,
	tRepIn TrustReportIn) (*TrustReport, error) {

	pcrmp, err := tpm2.ReadPCRs(rw, pcrSelection)
	if err != nil {
		return &TrustReport{}, err
	}

	pcrValues := map[int]PcrValue{}
	for key, pcr := range pcrmp {
		pcrValues[key] = PcrValue(pcr)
	}

	//invert int64 to []byte
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(tRepIn.nonce))

	attestation, _, err := tpm2.Quote(rw, AK.Handle, AK.Password, EmptyPassword,
		buf, pcrSelection, tpm2.AlgNull)

	if err != nil {
		return &TrustReport{}, err
	}

	pcrinfo := PcrInfo{pcrSelection, pcrValues, attestation}
	mainfest, err := GetManifest(tRepIn.imaPath)
	if err != nil {
		return &TrustReport{}, err
	}
	TRep = &TrustReport{pcrinfo, mainfest, tRepIn.clientId, tRepIn.clientInfo}
	return TRep, nil
}

func ActivateAC(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string,
	credServer, encryptedSecret []byte) (rerecoveredCredential []byte, err error) {

	recoveredCredential, err := tpm2.ActivateCredential(rw, activeHandle, keyHandle, activePassword,
		protectorPassword, credServer, encryptedSecret)
	if err != nil {
		fmt.Printf("ActivateCredential failed: %v \n", err)
	}
	return recoveredCredential, err
}

func GetAk(rw io.ReadWriter) (*AttestionKey, crypto.PublicKey, error) {
	ekPassword := EmptyPassword
	ekSel := MyPcrSelection
	ekHandle, EkPub, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, ekSel,
		EmptyPassword, ekPassword, DefaultKeyParams)
	if err != nil {
		return nil, nil, err
	}

	AK = &AttestionKey{}
	AK.Password = EmptyPassword
	AK.PcrSel = MyPcrSelection
	AK.Name, AK.Private, AK.Public, err = CreateAk(rw, ekHandle, ekPassword, AK.Password, AK.PcrSel)
	if err != nil {
		return nil, nil, err
	}

	AK.Handle, _, err = tpm2.Load(rw, ekHandle, ekPassword, AK.Public,
		AK.Private)
	if err != nil {
		return nil, nil, err
	}

	return AK, EkPub, err
}

func GetTrustReport(rw io.ReadWriter, tRepIn TrustReportIn) (*TrustReport, error) {
	return CreateTrustReport(rw, AK, MyPcrSelection, tRepIn)
}
func PrintInitRw()(io.ReadWriteCloser,tpmutil.Handle,error){
	tpmpath :="test"
	rw,_:=tpm2.OpenTPM(tpmpath)
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, PcrSelection7,
		"","", DefaultKeyParams)
	if err != nil {
		fmt.Errorf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)
	return rw,parentHandle,nil
}