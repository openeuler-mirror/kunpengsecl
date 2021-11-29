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
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os/exec"
	"strings"
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
		tpm2.FlushContext(tpm.dev, tpmutil.Handle(tpm.config.EK.Handle))
	}
	if tpm.config.IK.Handle != 0 {
		tpm2.FlushContext(tpm.dev, tpmutil.Handle(tpm.config.IK.Handle))
	}
	if err := tpm.dev.Close(); err != nil {
		log.Printf("close TPM error: %v\n", err)
	}
	tpm = nil
}

// Prepare method doing preparation steps for all the steps necessary for remote attesation, including prepare EKCert and create IK, according to the requirements given by TPMConfig
func (tpm *TPM) Prepare(config *TPMConfig) error {
	//create ek
	ekPassword := emptyPassword
	ekSel := pcrSelectionNil
	ekHandle, ekPub, err := tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, ekSel,
		emptyPassword, ekPassword, defaultKeyParams)
	if err != nil {
		return err
	}
	tpm.config.EK.Handle, tpm.config.EK.Pub = uint32(ekHandle), ekPub
	//try to get ekPem form nv, if failed ,create ekCert and write it to nv
	_, err = tpm.ReadEKCert()
	if err != nil {
		_, ekPem, e := tpm.generateEKCert()
		if e != nil {
			log.Printf("GenerateEKCert failed, error : %v \n", e)
			return err
		}
		tpm.WriteEKCert(ekPem)
	}
	//Create and save IK
	err = tpm.createIK(ekHandle, ekPassword, emptyPassword, pcrSelectionNil)

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
	if err := tpm2.NVUndefineSpace(tpm.dev, emptyPassword, tpm2.HandleOwner, ekIndex); err != nil {
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

// WriteEKCert writes the EK certificate(DER) into tpm NVRAM.
//   on TCG EK Credential Profile For TPM Family 2.0
//   Level 0 Version 2.4 Revision 3
//   https://trustedcomputinggroup.org/resource/tcg-ek-credential-profile-for-tpm-family-2-0/
//      0x01C00002      RSA 2048 EK Certificate
//      0x01C00003      RSA 2048 EK Nonce
//      0x01C00004      RSA 2048 EK Template
//      0x01C0000A      ECC NIST P256 EK Certificate
//      0x01C0000B      ECC NIST P256 EK Nonce
//      0x01C0000C      ECC NIST P256 EK Template
//      0x01C00012      RSA 2048 EK Certificate (H-1)
//      0x01C00014      ECC NIST P256 EK Certificate (H-2)
//      0x01C00016      ECC NIST P384 EK Certificate (H-3)
//      0x01C00018      ECC NIST P512 EK Certificate (H-4)
//      0x01C0001A      ECC SM2_P256 EK Certificate (H-5)
//      0x01C0001C      RSA 3072 EK Certificate (H-6)
//      0x01C0001E      RSA 4096 EK Certificate (H-7)
func (tpm *TPM) WriteEKCert(ekPem []byte) error {
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	err := tpm2.NVDefineSpace(tpm.dev, tpm2.HandleOwner, ekIndex,
		emptyPassword, emptyPassword, nil, attr, uint16(len(ekPem)))
	if err != nil {
		log.Printf("define NV space failed, error: %v", err)
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
		err = tpm2.NVWrite(tpm.dev, tpm2.HandleOwner, ekIndex, emptyPassword, ekPem[offset:end], offset)
		if err != nil {
			log.Printf("write NV failed, error: %v", err)
			return err
		}
		offset = end
	}
	return nil
}

// ReadEKCert reads the EK certificate(DER) from tpm NVRAM.
func (tpm *TPM) ReadEKCert() ([]byte, error) {
	ekPem, err := tpm2.NVReadEx(tpm.dev, ekIndex, tpm2.HandleOwner, emptyPassword, 0)
	if err != nil {
		log.Printf("read NV failed, error: %v", err)
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

//Generate an attestation key (IK) with the given options under the endorsement hierarchy.
func (tpm *TPM) createIK(parentHandle tpmutil.Handle, parentPassword, ikPassword string,
	ikSel tpm2.PCRSelection) error {

	privateIK, publicIK, _, _, _, err := tpm2.CreateKey(tpm.dev, parentHandle, ikSel,
		parentPassword, ikPassword, params)
	if err != nil {
		return err
	}

	//get IK handle
	ikHandle, _, err := tpm2.Load(tpm.dev, parentHandle, parentPassword, publicIK,
		privateIK)
	if err != nil {
		return err
	}

	//get IK name
	ikPub, akName, _, err := tpm2.ReadPublic(tpm.dev, ikHandle)
	if err != nil {
		return err
	}

	pub, err := ikPub.Key()
	if err != nil {
		return err
	}
	tpm.config.IK = &AttestationKey{
		Password: ikPassword,
		Private:  privateIK,
		Public:   publicIK,
		Pub:      pub,
		Name:     akName,
		Handle:   uint32(ikHandle),
	}

	return nil
}

// GetIKName method return the IK Name in bytes
func (tpm *TPM) GetIKName() []byte {
	return tpm.config.IK.Name
}

//ActivateIKCert method decrypted the IkCert from the input, and return it in PEM format
func (tpm *TPM) ActivateIKCert(in *IKCertInput) ([]byte, error) {
	recoveredCredential, err := tpm2.ActivateCredential(tpm.dev, tpmutil.Handle(tpm.config.IK.Handle),
		tpmutil.Handle(tpm.config.EK.Handle), tpm.config.IK.Password, tpm.config.EK.Password,
		in.CredBlob, in.EncryptedSecret)
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

	IKCert, err := pca.SymmetricDecrypt(alg, mode, recoveredCredential, in.DecryptParam, in.EncryptedCert)
	if err != nil {
		log.Printf("Decode IKCert failed: %v \n", err)
	}
	return IKCert, nil
}

//getIp function return the local IP address
//this function can only support ipv4
func getIp() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addrs {
		// Check whether the IP address is a loopback address
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("Can't fint ip")
}

// getClientInfo function return all client information in the format of a json string which is formated from a map[string]string
//TODO:fix values of version
func GetClientInfo() (string, error) {
	//Execute dmidecode shell-commands to acquire information
	//remind: need sudo permission
	var err error
	var out0 bytes.Buffer
	var out1 bytes.Buffer
	var out2 bytes.Buffer
	cmd0 := exec.Command("dmidecode", "-t", "0")
	cmd0.Stdout = &out0
	if err = cmd0.Run(); err != nil {
		return "", err
	}

	cmd1 := exec.Command("dmidecode", "-t", "1")
	cmd1.Stdout = &out1
	if err = cmd1.Run(); err != nil {
		return "", err
	}

	cmd2 := exec.Command("uname", "-a")
	cmd2.Stdout = &out2
	if err = cmd2.Run(); err != nil {
		return "", err
	}

	ip, err := getIp()
	if err != nil {
		return "", err
	}

	clientInfo := map[string]string{}
	//Intercept the information we need
	start0 := strings.Index(out0.String(), "BIOS Information")
	start1 := strings.Index(out1.String(), "System Information")
	clientInfo["bios"] = out0.String()[start0:]
	clientInfo["system"] = out1.String()[start1:]
	clientInfo["os"] = out2.String()
	clientInfo["ip"] = ip
	clientInfo["version"] = "1.0.0"

	fmt.Println(clientInfo)
	strCI, err := json.Marshal(clientInfo)
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

//Get the hash value of TrustReportIn, as user data of Quote
func (t *TrustReportIn) hash() []byte {
	buf := new(bytes.Buffer)
	b64 := make([]byte, 8)
	binary.BigEndian.PutUint64(b64, t.Nonce)
	buf.Write(b64)
	binary.BigEndian.PutUint64(b64, uint64(t.ClientId))
	buf.Write(b64)
	buf.WriteString(t.ClientInfo)
	bHash := sha256.New()
	bHash.Write(buf.Bytes())
	return bHash.Sum(nil)
}

//createTrustReport function collect some information, then return the TrustReport
func (tpm *TPM) createTrustReport(pcrSelection tpm2.PCRSelection, tRepIn *TrustReportIn) (*TrustReport, error) {
	pcrmp, err := tpm2.ReadPCRs(tpm.dev, pcrSelection)
	if err != nil {
		return &TrustReport{}, err
	}

	pcrValues := map[int32]string{}
	for key, pcr := range pcrmp {
		pcrValues[(int32)(key)] = hex.EncodeToString(pcr)
	}

	//we use TrustReportIn as user data of Quote to guarantee its integrity
	attestation, signature, err := tpm2.Quote(tpm.dev, tpmutil.Handle(tpm.config.IK.Handle),
		tpm.config.IK.Password, emptyPassword, tRepIn.hash(), pcrSelection, tpm2.AlgNull)
	if err != nil {
		return &TrustReport{}, err
	}

	jsonSig, err := json.Marshal(signature)
	if err != nil {
		return &TrustReport{}, err
	}

	algStrMap := map[tpm2.Algorithm]string{
		tpm2.AlgSHA1:   "SHA1",
		tpm2.AlgSHA256: "SHA256",
		tpm2.AlgSHA384: "SHA384",
		tpm2.AlgSHA512: "SHA512",
	}

	pcrinfo := PcrInfo{algStrMap[pcrSelection.Hash], pcrValues, PcrQuote{Quoted: attestation, Signature: jsonSig}}
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
	return tpm.createTrustReport(pcrSelectionAll, &tRepIn)
}
