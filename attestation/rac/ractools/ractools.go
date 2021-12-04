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
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/pca"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/pkg/errors"
)

const (
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
	IndexRsa2048EKCert     uint32 = 0x01C00002
	IndexRsa2048EKNonce    uint32 = 0x01C00003
	IndexRsa2048EKTemplate uint32 = 0x01C00004
	IndexECCP256EKCert     uint32 = 0x01C0000A
	IndexECCP256EKNonce    uint32 = 0x01C0000B
	IndexECCP256EKTemplate uint32 = 0x01C0000C
	IndexRsa2048EKCertH1   uint32 = 0x01C00012
	IndexECCP256EKCertH2   uint32 = 0x01C00014
	IndexECCP384EKCertH3   uint32 = 0x01C00016
	IndexECCP512EKCertH4   uint32 = 0x01C00018
	IndexSM2P256EKCertH5   uint32 = 0x01C0001A
	IndexRsa3072EKCertH6   uint32 = 0x01C0001C
	IndexRsa4096EKCertH7   uint32 = 0x01C0001E

	imaLogPath      = "/sys/kernel/security/ima/ascii_runtime_measurements"
	biosLogPath     = "/sys/kernel/security/tpm0/binary_bios_measurements"
	testImaLogPath  = "./ascii_runtime_measurements"
	testBiosLogPath = "./binary_bios_measurements"
	tpmDevPath      = "/dev/tpm0"
	blockSize       = 1024
	constDIMBIOS    = `# dmidecode 3.2
Getting SMBIOS data from sysfs.
SMBIOS 2.7 present.

Handle 0x0000, DMI type 0, 24 bytes
BIOS Information
	Vendor: American Megatrends Inc.
	Version: 4.6.5
	Release Date: 09/26/2013
	Address: 0xF0000
	Runtime Size: 64 kB
	ROM Size: 4096 kB
	Characteristics:
		PCI is supported
		BIOS is upgradeable
		BIOS shadowing is allowed
		Boot from CD is supported
		Selectable boot is supported
		EDD is supported
		Print screen service is supported (int 5h)
		8042 keyboard services are supported (int 9h)
		Printer services are supported (int 17h)
		ACPI is supported
		USB legacy is supported
		BIOS boot specification is supported
		Targeted content distribution is supported
		UEFI is supported
	BIOS Revision: 4.6`
	constDIMSYSTEM = `# dmidecode 3.2
Getting SMBIOS data from sysfs.
SMBIOS 2.7 present.

Handle 0x0001, DMI type 1, 27 bytes
System Information
	Manufacturer: Hasee Computer
	Product Name: CW35S
	Version: Not Applicable
	Serial Number: Not Applicable
	UUID: f0f59000-7a0a-0000-0000-000000000000
	Wake-up Type: Power Switch
	SKU Number: Not Applicable
	Family: Not Applicable`
)

var (
	tpm *TPM = nil
)

// OpenTPM creates a connection to either a simulator or a physical TPM device, returns a TPM object variable
// If useHW(use Hardware) is true, use physical tpm, otherwise use simulator
func OpenTPM(useHW bool) (*TPM, error) {
	var err error
	if tpm != nil {
		return tpm, nil
	}
	tpm = &TPM{
		config: TPMConfig{
			useHW:           useHW,
			IMALogPath:      imaLogPath,
			BIOSLogPath:     biosLogPath,
			ReportHashAlg:   "",
			EK:              &EndorsementKey{},
			IK:              &AttestationKey{},
			IsUseTestEKCert: false,
		},
		dev: nil,
	}
	if useHW {
		tpm.dev, err = tpm2.OpenTPM(tpmDevPath)
	} else {
		// GetWithFixedSeedInsecure behaves like Get() expect that all of the internal hierarchy
		// seeds are derived from the input seed. So every time we reopen the simulator,
		// we can always get the same ek for the same input
		tpm.dev, err = simulator.GetWithFixedSeedInsecure(int64(0))
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

// Prepare method doing preparation steps for all the steps necessary for remote attesation,
// including prepare EKCert and create IK, according to the requirements given by TPMConfig
// TODO:fix use of config
func (tpm *TPM) Prepare(config *TPMConfig, server string, generateEKCert func([]byte, string) ([]byte, error)) error {
	tpm.config.IsUseTestEKCert = config.IsUseTestEKCert
	// create ek
	ekPassword := emptyPassword
	ekSel := pcrSelectionNil
	ekHandle, ekPub, err := tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement, ekSel,
		emptyPassword, ekPassword, EKParams)
	if err != nil {
		return err
	}
	tpm.config.EK.Handle, tpm.config.EK.Pub = uint32(ekHandle), ekPub
	// try to get ekCert form nv, if failed ,create ekCert and write it to nv
	_, err = tpm.ReadEKCert(IndexRsa2048EKCert)
	var ekCert []byte
	if err != nil {
		if tpm.config.IsUseTestEKCert {
			result, _ := pem.Decode([]byte(ekPemTest))
			ekCert = result.Bytes
		} else {
			ekCert2, err2 := generateEKCert(tpm.GetEKPub(), server)
			if err2 != nil {
				log.Printf("GenerateEKCert failed, error : %v \n", err2)
				return err2
			}
			ekCert = ekCert2
		}
		tpm.WriteEKCert(IndexRsa2048EKCert, ekCert)
	}
	// Create and save IK
	err = tpm.createIK(ekHandle, ekPassword, emptyPassword, pcrSelectionNil)

	return err
}

// EraseEKCert erases the EK certificate from NVRAM.
func (tpm *TPM) EraseEKCert(idx uint32) {
	tpm2.NVUndefineSpace(tpm.dev, emptyPassword, tpm2.HandleOwner,
		tpmutil.Handle(idx))
}

// WriteEKCert writes the EK certificate(DER) into tpm NVRAM.
func (tpm *TPM) WriteEKCert(idx uint32, ekCert []byte) error {
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	err := tpm2.NVDefineSpace(tpm.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
		emptyPassword, emptyPassword, nil, attr, uint16(len(ekCert)))
	if err != nil {
		return err
	}
	l := uint16(len(ekCert))
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
		err = tpm2.NVWrite(tpm.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
			emptyPassword, ekCert[offset:end], offset)
		if err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// ReadEKCert reads the EK certificate from tpm NVRAM.
func (tpm *TPM) ReadEKCert(idx uint32) ([]byte, error) {
	ekDer, err := tpm2.NVReadEx(tpm.dev, tpmutil.Handle(idx), tpm2.HandleOwner, emptyPassword, 0)
	if err != nil {
		return nil, err
	}
	return ekDer, nil
}

// GetEKCert invoke ReadEKCert to get ekCertDer and convert it to PEM format.
// Note: Ensure that the read certificate is in der format,
// otherwise an error will be reported when calling this function.
func (tpm *TPM) GetEKCert() ([]byte, error) {
	// Read all of the ekDer with NVReadEx
	ekDer, err := tpm.ReadEKCert(IndexRsa2048EKCert)
	if err != nil {
		log.Printf("read NV failed, error: %v\n", err)
		return nil, err
	}

	//Convert the certificate in .der format to .pem format
	block := pem.Block{Type: "CERTIFICATE", Bytes: ekDer}
	ekPem := pem.EncodeToMemory(&block)
	return ekPem, nil
}

//GetEkPub return EKPub in der format
func (tpm *TPM) GetEKPub() []byte {
	derPub, err := x509.MarshalPKIXPublicKey(tpm.config.EK.Pub)
	if err != nil {
		log.Printf("GetEKPub failed, error: %v\n", err)
		return nil
	}

	return derPub
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
		parentPassword, ikPassword, IKParams)
	if err != nil {
		log.Printf("CreateIK failed, error: %v\n", err)
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

// getIp returns the local IPv4 address.
func getIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addrs {
		// Check whether the IP address is a loopback address
		ipnet, ok := address.(*net.IPNet)
		if ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// GetClientInfo returns json format client information.
// If useHW is false, use testfile
// TODO: add some other information
func GetClientInfo(useHW bool) (string, error) {
	//Execute dmidecode shell-commands to acquire information
	//remind: need sudo permission
	var err error
	var out0 bytes.Buffer
	var out1 bytes.Buffer
	var out2 bytes.Buffer
	var ip string
	if useHW {
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
	} else {
		out0.WriteString(constDIMBIOS)
		out1.WriteString(constDIMSYSTEM)
	}
	cmd2 := exec.Command("uname", "-a")
	cmd2.Stdout = &out2
	if err = cmd2.Run(); err != nil {
		return "", err
	}
	ip = getIP()

	clientInfo := map[string]string{}
	//Intercept the information we need
	start0 := strings.Index(out0.String(), "BIOS Information")
	start1 := strings.Index(out1.String(), "System Information")
	clientInfo["bios"] = out0.String()[start0:]
	clientInfo["system"] = out1.String()[start1:]
	clientInfo["os"] = out2.String()
	clientInfo["ip"] = ip
	clientInfo["version"] = "1.0.0"

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
func (tpm *TPM) createTrustReport(useHW bool, pcrSelection tpm2.PCRSelection, tRepIn *TrustReportIn) (*TrustReport, error) {
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

	var manifest []Manifest
	if useHW {
		manifest, err = getManifest(tpm.config.IMALogPath, tpm.config.BIOSLogPath)
		if err != nil {
			log.Printf("GetManifest Failed, error: %s", err)
		}
	} else {
		manifest, err = getManifest(testImaLogPath, testBiosLogPath)
		if err != nil {
			log.Printf("GetManifest Failed, error: %s", err)
		}
	}

	return &TrustReport{pcrinfo, manifest, tRepIn.ClientId, tRepIn.ClientInfo}, nil
}

//GetTrustReport method take a nonce input, generate and return the current trust report
func (tpm *TPM) GetTrustReport(nonce uint64, clientID int64) (*TrustReport, error) {
	clientInfo, err := GetClientInfo(tpm.config.useHW)
	if err != nil {
		log.Printf("GetClientInfo failed, error : %v \n", err)
	}
	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientID,
		ClientInfo: clientInfo,
	}
	return tpm.createTrustReport(tpm.config.useHW, pcrSelectionAll, &tRepIn)
}
