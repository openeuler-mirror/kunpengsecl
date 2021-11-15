package ractools

import (
	"crypto"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpm *TPM = &TPM{
		config: TPMConfig{
			IMALogPath:    "/sys/kernel/security/ima/ascii_runtime_measurements",
			BIOSLogPath:   "/sys/kernel/security/tpm0/binary_bios_measurements",
			EKAlg:         "",
			AKAlg:         "",
			ReportHashAlg: "",
			AK:            nil,
		},
		dev: nil,
	}
	tpmpath       = "/dev/tpm0"
	isPhysicalTpm bool
	TRep          *TrustReport
	AK            *AttestationKey
	EkPub         crypto.PublicKey
)

func GetManifest(imaPath, biosPath string) ([]Manifest, error) {
	var manifest []Manifest
	f, err := ioutil.ReadFile(imaPath)
	if err == nil {
		manifest = append(manifest, Manifest{Type: "ima", Content: f})
	}

	f, err = ioutil.ReadFile(biosPath)
	if err == nil {
		manifest = append(manifest, Manifest{Type: "bios", Content: f})
	}

	return manifest, err
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

func CreateTrustReport(rw io.ReadWriter, AK *AttestationKey, pcrSelection tpm2.PCRSelection,
	tRepIn TrustReportIn) (*TrustReport, error) {

	pcrmp, err := tpm2.ReadPCRs(rw, pcrSelection)
	if err != nil {
		return &TrustReport{}, err
	}

	pcrValues := map[int]string{}
	for key, pcr := range pcrmp {
		var value string
		for _, c := range pcr {
			value += (string)(c + 48) //invert byte(0) into string(0)
		}
		pcrValues[key] = value
	}

	//invert uint64 to []byte
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(tRepIn.Nonce))

	attestation, _, err := tpm2.Quote(rw, AK.Handle, AK.Password, EmptyPassword,
		buf, pcrSelection, tpm2.AlgNull)

	if err != nil {
		return &TrustReport{}, err
	}

	pcrinfo := PcrInfo{"SHA1", pcrValues, attestation}
	mainfest, err := GetManifest(tpm.config.IMALogPath, tpm.config.BIOSLogPath)
	if err != nil {
		log.Printf("Can't find manifest-file : %v \n", err)
	}
	TRep = &TrustReport{pcrinfo, mainfest, tRepIn.ClientId, tRepIn.ClientInfo}
	return TRep, nil
}

func ActivateAC(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string,
	credServer, encryptedSecret []byte) (rerecoveredCredential []byte, err error) {

	recoveredCredential, err := tpm2.ActivateCredential(rw, activeHandle, keyHandle, activePassword,
		protectorPassword, credServer, encryptedSecret)
	if err != nil {
		log.Printf("ActivateCredential failed: %v \n", err)
	}
	return recoveredCredential, err
}

func GetAk() (*AttestationKey, crypto.PublicKey, error) {
	if tpm.dev == nil {
		//first, try to open physical tpm
		var err error
		tpm.dev, err = tpm2.OpenTPM(tpmpath)
		isPhysicalTpm = true
		if err != nil {
			//try to open simulator
			tpm.dev, err = simulator.Get()
			isPhysicalTpm = false
			if err != nil {
				log.Printf("Simulator initialization failed: %v", err)
			}
		}
	}

	ekPassword := EmptyPassword
	ekSel := MyPcrSelection
	ekHandle, EkPub, err := tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, ekSel,
		EmptyPassword, ekPassword, DefaultKeyParams)
	if err != nil {
		return nil, nil, err
	}
	defer tpm2.FlushContext(tpm.dev, ekHandle)

	AK = &AttestationKey{}
	AK.Password = EmptyPassword
	AK.PcrSel = MyPcrSelection
	AK.Name, AK.Private, AK.Public, err = CreateAk(tpm.dev, ekHandle, ekPassword, AK.Password, AK.PcrSel)
	if err != nil {
		return nil, nil, err
	}

	AK.Handle, _, err = tpm2.Load(tpm.dev, ekHandle, ekPassword, AK.Public,
		AK.Private)
	if err != nil {
		return nil, nil, err
	}

	return AK, EkPub, err
}

func GetTrustReport(tRepIn TrustReportIn) (*TrustReport, error) {
	if tpm.dev == nil {
		//first, try to open physical tpm
		var err error
		tpm.dev, err = tpm2.OpenTPM(tpmpath)
		isPhysicalTpm = true
		if err != nil {
			//try to open simulator
			tpm.dev, err = simulator.Get()
			isPhysicalTpm = false
			if err != nil {
				log.Printf("Simulator initialization failed: %v", err)
			}
		}
	}

	if AK == nil {
		AK, _, _ = GetAk()
	}

	return CreateTrustReport(tpm.dev, AK, MyPcrSelection, tRepIn)
}

func WriteEkCert(ekPath string) error {

	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear

	data, err := ioutil.ReadFile(ekPath)
	if err != nil {
		log.Printf("WriteEkCert failed: %v", err)
	}

	// Undefine the space, just in case the previous run of this test failed
	// to clean up.
	if err := tpm2.NVUndefineSpace(tpm.dev, EmptyPassword, tpm2.HandleOwner, ekidx); err != nil {
		log.Printf("(not a failure) NVUndefineSpace at index 0x%x failed: %v", ekidx, err)
	}

	// Define space in NV storage and clean up afterwards or subsequent runs will fail.
	l := len(data)

	if err := tpm2.NVDefineSpace(tpm.dev,
		tpm2.HandleOwner,
		ekidx,
		EmptyPassword,
		EmptyPassword,
		nil,
		attr,
		uint16(len(data)),
	); err != nil {
		log.Printf("NVDefineSpace failed: %v", err)
		return err
	}

	// Write the data

	offset := (uint16)(0)
	for l > 0 {
		end := offset + 1024
		if l < 1024 {
			end = offset + (uint16)(l)
		}
		in := data[offset:end]
		if err := tpm2.NVWrite(tpm.dev, tpm2.HandleOwner, ekidx, EmptyPassword, in, offset); err != nil {
			log.Printf("NVWrite failed: %v", err)
			return err
		}
		offset += 1024
		l -= 1024
	}
	return nil
}

func GetEkCert() (string, error) {
	// Make sure the public area of the index can be read
	_, err := tpm2.NVReadPublic(tpm.dev, ekidx)
	if err != nil {
		log.Printf("NVReadPublic failed: %v", err)
		//if the ekIndex can't be read, write ekCert to the area of the index
		WriteEkCert("./ekce.pem")
	}

	// Read all of the data with NVReadEx
	outdata, err := tpm2.NVReadEx(tpm.dev, ekidx, tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		log.Printf("NVReadEx failed: %v", err)
		return "", err
	}

	return (string)(outdata), nil
}
