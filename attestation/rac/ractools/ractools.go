package ractools

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	rw            io.ReadWriteCloser = nil
	tpmpath                          = "/dev/tpm0"
	isPhysicalTpm bool
	TRep          *TrustReport
	AK            *AttestionKey
	EkPub         crypto.PublicKey
)

func GetManifest(imapath string) ([]Manifest, error) {
	f, err := ioutil.ReadFile(imapath)
	if err != nil {
		return nil, err
	}
	var manifest []Manifest
	s := make([]string, 5, 6)
	var j int = 0
	for i := range f {
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
	defer tpm2.FlushContext(rw, akHandle)

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

	//invert uint64 to []byte
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(tRepIn.Nonce))

	attestation, _, err := tpm2.Quote(rw, AK.Handle, AK.Password, EmptyPassword,
		buf, pcrSelection, tpm2.AlgNull)

	if err != nil {
		return &TrustReport{}, err
	}

	pcrinfo := PcrInfo{pcrSelection, pcrValues, attestation}
	mainfest, err := GetManifest(tRepIn.ImaPath)
	if err != nil {
		fmt.Printf("Can't find ima-file : %v \n", err)
	}
	TRep = &TrustReport{pcrinfo, mainfest, tRepIn.ClientId, tRepIn.ClientInfo}
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

func GetAk() (*AttestionKey, crypto.PublicKey, error) {
	if rw == nil {
		//first, try to open physical tpm
		var err error
		rw, err = tpm2.OpenTPM(tpmpath)
		isPhysicalTpm = true
		if err != nil {
			//try to open simulator
			rw, err = simulator.Get()
			isPhysicalTpm = false
			if err != nil {
				fmt.Printf("Simulator initialization failed: %v", err)
			}
		}
	}

	ekPassword := EmptyPassword
	ekSel := MyPcrSelection
	ekHandle, EkPub, err := tpm2.CreatePrimary(rw, tpm2.HandleEndorsement, ekSel,
		EmptyPassword, ekPassword, DefaultKeyParams)
	if err != nil {
		return nil, nil, err
	}
	defer tpm2.FlushContext(rw, ekHandle)

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

func GetTrustReport(tRepIn TrustReportIn) (*TrustReport, error) {
	if rw == nil {
		//first, try to open physical tpm
		var err error
		rw, err = tpm2.OpenTPM(tpmpath)
		isPhysicalTpm = true
		if err != nil {
			//try to open simulator
			rw, err = simulator.Get()
			isPhysicalTpm = false
			if err != nil {
				fmt.Printf("Simulator initialization failed: %v", err)
			}
		}
	}

	if AK == nil {
		AK, _, _ = GetAk()
	}

	return CreateTrustReport(rw, AK, MyPcrSelection, tRepIn)
}
