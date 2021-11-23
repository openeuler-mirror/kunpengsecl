package ractools

import (
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	tpm     *TPM
	tpmpath = "/dev/tpm0"
	TRep    *TrustReport
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

func CreateIK(rw io.ReadWriter, parentHandle tpmutil.Handle, parentPassword, IKPassword string,
	IKSel tpm2.PCRSelection) ([]byte, []byte, []byte, error) {

	privateIK, publicIK, _, _, _, err := tpm2.CreateKey(rw, parentHandle, IKSel,
		parentPassword, IKPassword, Params)
	if err != nil {
		return nil, nil, nil, err
	}

	akHandle, _, err := tpm2.Load(rw, parentHandle, parentPassword, publicIK,
		privateIK)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tpm2.FlushContext(rw, akHandle)

	_, akname, _, err := tpm2.ReadPublic(rw, akHandle)
	if err != nil {
		return nil, nil, nil, err
	}

	return akname, privateIK, publicIK, nil
}

func CreateTrustReport(rw io.ReadWriter, IK *AttestationKey, pcrSelection tpm2.PCRSelection,
	tRepIn TrustReportIn) (*TrustReport, error) {

	pcrmp, err := tpm2.ReadPCRs(rw, pcrSelection)
	if err != nil {
		return &TrustReport{}, err
	}

	pcrValues := map[int32]string{}
	for key, pcr := range pcrmp {
		var value string
		for _, c := range pcr {
			value += (string)(c + 48) //invert byte(0) into string(0)
		}
		pcrValues[(int32)(key)] = value
	}

	//invert uint64 to []byte
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(tRepIn.Nonce))

	attestation, signature, err := tpm2.Quote(rw, IK.Handle, IK.Password, EmptyPassword,
		buf, pcrSelection, tpm2.AlgNull)

	if err != nil {
		return &TrustReport{}, err
	}

	pcrinfo := PcrInfo{"SHA1", pcrValues, PcrQuote{Quoted: attestation, Signature: signature.RSA.Signature}}
	mainfest, err := GetManifest(tpm.config.IMALogPath, tpm.config.BIOSLogPath)
	if err != nil {
		log.Printf("GetManifest Failed, error: %s", err)
	}
	TRep = &TrustReport{pcrinfo, mainfest, tRepIn.ClientId, tRepIn.ClientInfo}
	return TRep, nil
}

func GetIK() error {
	var err error

	tpm.config.IK = &AttestationKey{}
	tpm.config.IK.Password = EmptyPassword
	tpm.config.IK.PcrSel = MyPcrSelection
	tpm.config.IK.Name, tpm.config.IK.Private, tpm.config.IK.Public, err = CreateIK(tpm.dev, tpm.config.EK.Handle, EmptyPassword, tpm.config.IK.Password, tpm.config.IK.PcrSel)
	if err != nil {
		log.Printf("CreateIK failed, error : %v \n", err)
		return err
	}

	tpm.config.IK.Handle, _, err = tpm2.Load(tpm.dev, tpm.config.EK.Handle, EmptyPassword, tpm.config.IK.Public,
		tpm.config.IK.Private)
	if err != nil {
		log.Printf("Load IK failed, error : %v \n", err)
		return err
	}

	return nil
}

func WriteEkCert(ekPath string) error {

	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear

	data, err := ioutil.ReadFile(ekPath)
	if err != nil {
		log.Printf("WriteEkCert failed, error : %v \n", err)
	}

	// Undefine the space, just in case the previous run of this test failed
	// to clean up.
	if err := tpm2.NVUndefineSpace(tpm.dev, EmptyPassword, tpm2.HandleOwner, ekidx); err != nil {
		log.Printf("(not a failure) NVUndefineSpace at index 0x%x failed, error : %v \n", ekidx, err)
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
		log.Printf("NVDefineSpace failed, error : %v \n", err)
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
			log.Printf("NVWrite failed, error : %v \n", err)
			return err
		}
		offset += 1024
		l -= 1024
	}
	return nil
}

// OpenTPM create a connection to either a simulator or a physical TPM device, return a TPM object variable
func OpenTPM(useSimulator bool) (*TPM, error) {
	var err error
	tpm = &TPM{
		config: TPMConfig{
			IMALogPath:    "/sys/kernel/security/ima/ascii_runtime_measurements",
			BIOSLogPath:   "/sys/kernel/security/tpm0/binary_bios_measurements",
			ReportHashAlg: "",
			EK:            &EndorsementKey{},
			IK:            &AttestationKey{},
		},
		dev: nil,
	}

	if useSimulator {
		tpm.dev, err = simulator.Get()
	} else {
		tpm.dev, err = tpm2.OpenTPM(tpmpath)
	}
	if err != nil {
		log.Printf("OpenTPM failed, error : %v \n", err)
	}

	return tpm, err
}

// Prepare method doing preparation steps for all the steps necessary for remote attesation, including prepare EKCert and create IK, according to the requirements given by TPMConfig
func (tpm *TPM) Prepare(config *TPMConfig) error {
	//Create ek and ekCert, then write EkCert to NVStorage

	//create ek
	ekPassword := EmptyPassword
	ekSel := MyPcrSelection
	var err error
	tpm.config.EK.Handle, tpm.config.EK.Pub, err = tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, ekSel,
		EmptyPassword, ekPassword, DefaultKeyParams)
	if err != nil {
		return err
	}

	//create ekCert
	/*
			var cmd *exec.Cmd
			cmd = exec.Command("openssl", "genrsa", "-out", "key.pem")
			if err = cmd.Run(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

		//write ekCert
		WriteEkCert(ekPath)
	*/
	ekPem := `-----BEGIN CERTIFICATE-----
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
	ioutil.WriteFile("ekPem", ([]byte)(ekPem), 0777)
	WriteEkCert("ekPem")

	//Create and save IK
	err = GetIK()

	return err
}

// GetEKCert method return a EKCert in PEM format
func (tpm *TPM) GetEKCert() (string, error) {
	// Make sure the public area of the index can be read
	_, err := tpm2.NVReadPublic(tpm.dev, ekidx)
	if err != nil {
		log.Printf("NVReadPublic failed, error : %v \n", err)
	}

	// Read all of the data with NVReadEx
	outdata, err := tpm2.NVReadEx(tpm.dev, ekidx, tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		log.Printf("NVReadEx failed, error : %v \n", err)
		return "", err
	}

	return (string)(outdata), nil
}

// GetIKPub method return the IK pubkey in PEM format
func (tpm *TPM) GetIKPub() string {
	block := &pem.Block{
		Type:    "IK PUBLIC KEY",
		Headers: map[string]string{},
		Bytes:   tpm.config.IK.Public,
	}

	ans := pem.EncodeToMemory(block)
	return (string)(ans)
}

// GetIKName method return the IK Name in bytes
func (tpm *TPM) GetIKName() []byte {
	return tpm.config.IK.Name
}

//ActivateIKCert method decrypted the IkCert from the input, and return it in PEM format
//func (tpm *TPM) ActivateIKCert(in *IKCertInput) (string, error)

func ActivateAC(rw io.ReadWriter, activeHandle, keyHandle tpmutil.Handle, activePassword, protectorPassword string,
	credServer, encryptedSecret []byte) (rerecoveredCredential []byte, err error) {

	recoveredCredential, err := tpm2.ActivateCredential(rw, activeHandle, keyHandle, activePassword,
		protectorPassword, credServer, encryptedSecret)
	if err != nil {
		log.Printf("ActivateCredential failed: %v \n", err)
	}
	return recoveredCredential, err
}

//GetTrustReport method take a nonce input, generate and return the current trust report
func (tpm *TPM) GetTrustReport(nonce uint64, clientID int64) (*TrustReport, error) {
	clientInfo, err := GetClientInfo()
	if err != nil {
		log.Printf("GetClientInfo failed, error : %v \n", err)
	}
	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientID,
		ClientInfo: clientInfo,
	}
	return CreateTrustReport(tpm.dev, tpm.config.IK, MyPcrSelection, tRepIn)
}

// Close method close an open tpm device
func (tpm *TPM) Close() error {
	//remove ekHandle and ikHandle from tpm
	tpm2.FlushContext(tpm.dev, tpm.config.EK.Handle)
	tpm2.FlushContext(tpm.dev, tpm.config.IK.Handle)
	tpm.config = TPMConfig{}
	return tpm.dev.Close()
}

// GetClientInfo function return all client information in the format of a json string which is formated from a map[string]string
func GetClientInfo() (string, error) {
	return "", nil
}

//暂时放这里，可能没有用后续再调整
//GetEkPub return EKPub in pem format
func (tpm *TPM) GetEKPub() string {
	block := &pem.Block{
		Type:    "EK PUBLIC KEY",
		Headers: map[string]string{},
		Bytes:   []byte(tpm.config.EK.Pub.(*rsa.PublicKey).N.Bytes()),
	}

	return (string)(pem.EncodeToMemory(block))
}
