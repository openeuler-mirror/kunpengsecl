/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
PURPOSE.
See the Mulan PSL v2 for more details.

Author: jiayunhao
Create: 2021-09-17
Description: Define the structure for the TPM operation.
*/

package ractools

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/pkg/errors"
)

const (
	imaLogPath  = "/sys/kernel/security/ima/ascii_runtime_measurements"
	biosLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"
	tpmDevPath  = "/dev/tpm0"
	blockSize   = 1024
)

var (
	tpm *TPM = nil
)

// OpenTPM creates a connection to either a simulator or a physical TPM device, returns a TPM object variable
func OpenTPM(useHW bool) (*TPM, error) {
	var err error
	if tpm != nil {
		return tpm, nil
	}
	tpm = &TPM{
		config: TPMConfig{
			isPhysicalTpm: useHW,
			IMALogPath:    imaLogPath,
			BIOSLogPath:   biosLogPath,
			ReportHashAlg: "",
			EK:            &EndorsementKey{},
			IK:            &AttestationKey{},
		},
		dev: nil,
	}
	if useHW {
		tpm.dev, err = tpm2.OpenTPM(tpmDevPath)
	} else {
		tpm.dev, err = simulator.Get()
	}
	if err != nil {
		tpm = nil
	}
	return tpm, err
}

// Close closes an open tpm device and flushes tpm resources.
func (tpm *TPM) Close() {
	if tpm == nil {
		return
	}
	//remove ekHandle and ikHandle from tpm
	if tpm.config.EK.Handle != 0 {
		tpm2.FlushContext(tpm.dev, tpm.config.EK.Handle)
	}
	if tpm.config.IK.Handle != 0 {
		tpm2.FlushContext(tpm.dev, tpm.config.IK.Handle)
	}
	if err := tpm.dev.Close(); err != nil {
		log.Printf("close TPM error: %v\n", err)
	}
	tpm = nil
}

// Prepare method doing preparation steps for all the steps necessary for remote attesation, including prepare EKCert and create IK, according to the requirements given by TPMConfig
func (tpm *TPM) Prepare(config *TPMConfig) error {
	//create ek
	ekPassword := EmptyPassword
	ekSel := MyPcrSelection
	var err error
	tpm.config.EK.Handle, tpm.config.EK.Pub, err = tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, ekSel,
		EmptyPassword, ekPassword, DefaultKeyParams)
	if err != nil {
		return err
	}
	//try to get ekPem form nv, if failed ,create ekCert and write it to nv
	_, err = tpm.ReadEKCert()
	if err != nil {
		_, ekPem, e := tpm.generateEKCert()
		if e != nil {
			log.Printf("GenerateEKCert failed, error : %v \n", e)
		}
		tpm.WriteEKCert(ekPem)
	}
	//Create and save IK
	err = tpm.createIK(tpm.config.EK.Handle, ekPassword, EmptyPassword, tpm2.PCRSelection{})
	return err
}

func (tpm *TPM) generateEKCert() (*x509.Certificate, []byte, error) {
	template := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		NotBefore:      time.Now().Add(-10 * time.Second),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		IsCA:           false,
		MaxPathLenZero: true,
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
	}
	pcaCert, err := pca.DecodeCert(pca.CertPEM)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to decode cert while generate EKCert")
	}
	pcaPriv, err := pca.DecodePrivkey(pca.PrivPEM)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to decode key while generate EKCert")
	}
	ekCert, ekPem, err := pca.GenerateCert(&template, pcaCert, (tpm.config.EK.Pub).(*rsa.PublicKey), pcaPriv)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate EKCert")
	}
	return ekCert, ekPem, err
}

// EraseEKCert erases the EK certificate from NVRAM.
func (tpm *TPM) EraseEKCert() {
	if err := tpm2.NVUndefineSpace(tpm.dev, EmptyPassword, tpm2.HandleOwner, ekIndex); err != nil {
		switch err := err.(type) {
		case nil:
			fmt.Printf("1\n")
		case tpm2.Error:
			fmt.Printf("2. %v\n", err)
			if err.Code != tpm2.RCNVLocked {
				fmt.Printf("3. %v\n", err)
			}
		default:
			fmt.Printf("4. %v\n", err)
		}
		log.Printf("erase EK Certificate at index 0x%x failed, error: %v\n", ekIndex, err)
	}
}

// WriteEKCert writes the EK certificate into NVRAM.
func (tpm *TPM) WriteEKCert(ekPem []byte) error {
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	err := tpm2.NVDefineSpace(tpm.dev, tpm2.HandleOwner, ekIndex,
		EmptyPassword, EmptyPassword, nil, attr, uint16(len(ekPem)))
	if err != nil {
		log.Printf("define NV space failed, error: %v\n", err)
		return err
	}
	l := uint16(len(ekPem))
	offset := uint16(0)
	end := uint16(0)
	for l > 0 {
		if l < blockSize {
			end = offset + l
			l = 0
		} else {
			end = offset + blockSize
			l -= blockSize
		}
		err = tpm2.NVWrite(tpm.dev, tpm2.HandleOwner, ekIndex, EmptyPassword, ekPem[offset:end], offset)
		if err != nil {
			log.Printf("write NV failed, error: %v \n", err)
			return err
		}
		offset = end
	}
	return nil
}

// ReadEKCert reads the EK certificate from NVRAM with PEM format.
func (tpm *TPM) ReadEKCert() ([]byte, error) {
	// Read all of the ekPem with NVReadEx
	ekPem, err := tpm2.NVReadEx(tpm.dev, ekIndex, tpm2.HandleOwner, EmptyPassword, 0)
	if err != nil {
		log.Printf("read NV failed, error: %v\n", err)
		return nil, err
	}
	return ekPem, nil
}

//暂时放这里，可能没有用后续再调整
//GetEkPub return EKPub in pem format
func (tpm *TPM) GetEKPub() string {
	derPub, err := x509.MarshalPKIXPublicKey(tpm.config.EK.Pub)
	if err != nil {
		return ""
	}
	block := &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{},
		Bytes:   derPub,
	}

	return (string)(pem.EncodeToMemory(block))
}

// GetIKPub method return the IK pubkey in PEM format
func (tpm *TPM) GetIKPub() []byte {
	derPub, err := x509.MarshalPKIXPublicKey(tpm.config.IK.Pub)
	if err != nil {
		return []byte{}
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPub,
	}

	ans := pem.EncodeToMemory(block)
	return ans
}

func (tpm *TPM) createIK(parentHandle tpmutil.Handle, parentPassword, IKPassword string,
	IKSel tpm2.PCRSelection) error {

	privateIK, publicIK, _, _, _, err := tpm2.CreateKey(tpm.dev, parentHandle, IKSel,
		parentPassword, IKPassword, Params)
	if err != nil {
		return err
	}

	akHandle, _, err := tpm2.Load(tpm.dev, parentHandle, parentPassword, publicIK,
		privateIK)
	if err != nil {
		return err
	}

	akPub, akName, _, err := tpm2.ReadPublic(tpm.dev, akHandle)
	if err != nil {
		return err
	}

	pub, err := akPub.Key()
	if err != nil {
		return err
	}
	tpm.config.IK = &AttestationKey{}
	tpm.config.IK.Password = IKPassword
	tpm.config.IK.PcrSel = MyPcrSelection
	tpm.config.IK.Private = privateIK
	tpm.config.IK.Public = publicIK
	tpm.config.IK.Pub = pub
	tpm.config.IK.Name = akName
	tpm.config.IK.Handle = akHandle

	return nil
}

// GetIKName method return the IK Name in bytes
func (tpm *TPM) GetIKName() []byte {
	return tpm.config.IK.Name
}

//ActivateIKCert method decrypted the IkCert from the input, and return it in PEM format
func (tpm *TPM) ActivateIKCert(in *IKCertInput) ([]byte, error) {
	recoveredCredential, err := tpm2.ActivateCredential(tpm.dev, tpm.config.IK.Handle, tpm.config.EK.Handle, tpm.config.IK.Password,
		tpm.config.EK.Password, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		log.Printf("ActivateCredential failed: %v \n", err)
	}

	var alg, mode uint16
	switch in.DecryptAlg {
	case pca.Encrypt_Alg: //AES128_CBC
		alg, mode = pca.AlgAES, pca.AlgCBC
	default:
		log.Printf("ActivateCredential failed: unsupported algorithm %s\n", in.DecryptAlg)
		return nil, errors.Errorf("unsupported algorithm: %s", in.DecryptAlg)
	}

	//
	IKCert, err := pca.SymmetricDecrypt(alg, mode, recoveredCredential, in.IV, in.EncryptedCert)
	if err != nil {
		log.Printf("Decode IKCert failed: %v \n", err)
	}
	return IKCert, nil
}

// GetClientInfo function return all client information in the format of a json string which is formated from a map[string]string
func GetClientInfo() (string, error) {
	ci := map[string]string{"version": "1.0.0"}
	strCI, err := json.Marshal(ci)
	return string(strCI), err
}

func getManifest(imaPath, biosPath string) ([]Manifest, error) {
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

func (tpm *TPM) createTrustReport(IK *AttestationKey, pcrSelection tpm2.PCRSelection,
	tRepIn TrustReportIn) (*TrustReport, error) {

	pcrmp, err := tpm2.ReadPCRs(tpm.dev, pcrSelection)
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

	attestation, signature, err := tpm2.Quote(tpm.dev, IK.Handle, IK.Password, EmptyPassword,
		buf, pcrSelection, tpm2.AlgNull)

	if err != nil {
		return &TrustReport{}, err
	}

	pcrinfo := PcrInfo{"SHA1", pcrValues, PcrQuote{Quoted: attestation, Signature: signature.RSA.Signature}}
	mainfest, err := getManifest(tpm.config.IMALogPath, tpm.config.BIOSLogPath)
	if err != nil {
		log.Printf("GetManifest Failed, error: %s", err)
	}
	return &TrustReport{pcrinfo, mainfest, tRepIn.ClientId, tRepIn.ClientInfo}, nil
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
	return tpm.createTrustReport(tpm.config.IK, MyPcrSelection, tRepIn)
}
