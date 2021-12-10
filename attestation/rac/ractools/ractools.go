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
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/config"
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
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

	tpmDevPath1  = "/dev/tpmrm0"
	tpmDevPath2  = "/dev/tpm0"
	blockSize    = 1024
	constDMIBIOS = `# dmidecode 3.2
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
	constDMISYSTEM = `# dmidecode 3.2
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
	tpm            *TPM = nil
	errWrongParams      = errors.New("wrong input parameter")
	errFailTPMInit      = errors.New("couldn't start tpm or init key/certificate")
)

// OpenTPM uses either a physical TPM device(default/useHW=true) or a
// simulator(-t/useHw=false), returns a global TPM object variable.
func OpenTPM(useHW bool, conf *TPMConfig) (*TPM, error) {
	if tpm != nil {
		return tpm, nil
	}
	if conf == nil {
		return nil, errWrongParams
	}
	tpm = &TPM{
		config: conf,
		useHW:  useHW,
		dev:    nil,
	}
	if useHW {
		return openTpmChip(tpm)
	}
	return openTpmSimulator(tpm)
}

// openTpmChip opens TPM hardware chip and reads EC from NVRAM.
// NOTICE:
//   User should use tbprovisioner command tool to write the EC
// into TPM NVRAM before running raagent or the TPM chip already
// has EC in NVRAM when it comes from manufactories.
func openTpmChip(tpm *TPM) (*TPM, error) {
	var err error
	tpm.dev, err = tpm2.OpenTPM(tpmDevPath1)
	if err != nil {
		tpm.dev, err = tpm2.OpenTPM(tpmDevPath2)
	}
	if err != nil {
		return nil, errFailTPMInit
	}
	ekCertDer, err := tpm.ReadNVRAM(IndexRsa2048EKCert) // DER format??
	if err != nil {
		return nil, errFailTPMInit
	}
	ekCert, err := x509.ParseCertificate(ekCertDer)
	if err != nil {
		return nil, errFailTPMInit
	}
	cfg := config.GetDefault(config.ConfClient)
	cfg.SetEKeyCert(ekCert)
	return tpm, nil
}

// openTpmSimulator opens TPM simulator.
// EK/IK key and certificate should be loaded/generated from files by config.
func openTpmSimulator(tpm *TPM) (*TPM, error) {
	// GetWithFixedSeedInsecure behaves like Get() expect that all of the
	// internal hierarchy seeds are derived from the input seed. So every
	// time we reopen the simulator, we can always get the same ek for the
	// same input.
	var err error
	tpm.dev, err = simulator.GetWithFixedSeedInsecure(int64(0))
	if err != nil {
		return nil, errFailTPMInit
	}
	return tpm, nil
}

// Close closes an open tpm device and flushes tpm resources.
func (tpm *TPM) Close() {
	if tpm == nil {
		return
	}
	if tpm.useHW {
		//remove ekHandle and ikHandle from hw tpm
		if tpm.EK.Handle != 0 {
			tpm2.FlushContext(tpm.dev, tpmutil.Handle(tpm.EK.Handle))
		}
		if tpm.IK.Handle != 0 {
			tpm2.FlushContext(tpm.dev, tpmutil.Handle(tpm.IK.Handle))
		}
	}
	if err := tpm.dev.Close(); err != nil {
		log.Printf("close TPM error: %v\n", err)
	}
	tpm = nil
}

// DefineNVRAM defines the index space as size length in the NVRAM
func (tpm *TPM) DefineNVRAM(idx uint32, size uint16) error {
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead | tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	return tpm2.NVDefineSpace(tpm.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
		emptyPassword, emptyPassword, nil, attr, size)
}

// UndefineNVRAM frees the index space in the NVRAM
func (tpm *TPM) UndefineNVRAM(idx uint32) error {
	return tpm2.NVUndefineSpace(tpm.dev, emptyPassword, tpm2.HandleOwner,
		tpmutil.Handle(idx))
}

// WriteNVRAM writes the data at index into the NVRAM
func (tpm *TPM) WriteNVRAM(idx uint32, data []byte) error {
	l := uint16(len(data))
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
		err := tpm2.NVWrite(tpm.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
			emptyPassword, data[offset:end], offset)
		if err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// ReadNVRAM reads the data at index from the NVRAM
func (tpm *TPM) ReadNVRAM(idx uint32) ([]byte, error) {
	return tpm2.NVReadEx(tpm.dev, tpmutil.Handle(idx), tpm2.HandleOwner, emptyPassword, 0)
}

// GenerateEPubKeyTest generates the ek key for test by tpm2 and get the public part
func (tpm *TPM) GenerateEPubKeyTest() error {
	var err error
	tpm.EK.Handle, tpm.EK.Pub, err = tpm2.CreatePrimary(tpm.dev, tpm2.HandleEndorsement,
		pcrSelectionNil, emptyPassword, emptyPassword, EKParams)
	if err != nil {
		return err
	}
	return nil
}

// GenerateIPrivKeyTest generates the ik key under ek for test by tpm2, gets the private,
// public, name fields to use later
func (tpm *TPM) GenerateIPrivKeyTest() error {
	var err error
	tpm.IK.Private, tpm.IK.Public, _, _, _, err = tpm2.CreateKey(tpm.dev, tpm.EK.Handle,
		pcrSelectionNil, emptyPassword, emptyPassword, IKParams)
	if err != nil {
		log.Printf("Client: GenerateIPrivKeyTest %v\n", err)
		return err
	}
	tpm.IK.Handle, _, err = tpm2.Load(tpm.dev, tpm.EK.Handle, emptyPassword,
		tpm.IK.Public, tpm.IK.Private)
	if err != nil {
		return err
	}
	ikPub, akName, _, err := tpm2.ReadPublic(tpm.dev, tpm.IK.Handle)
	if err != nil {
		return err
	}
	pub, err := ikPub.Key()
	if err != nil {
		return err
	}
	tpm.IK.Password = emptyPassword
	tpm.IK.Name = akName
	tpm.IK.Pub = pub
	return nil
}

// ActivateIKCert decrypts the IkCert from the input, and return it in PEM format
func (tpm *TPM) ActivateIKCert(in *IKCertInput) ([]byte, error) {
	recoveredCredential, err := tpm2.ActivateCredential(tpm.dev, tpm.IK.Handle, tpm.EK.Handle,
		emptyPassword, emptyPassword, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		return nil, err
	}

	var alg, mode uint16
	switch in.DecryptAlg {
	case pca.Encrypt_Alg: //AES128_CBC
		alg, mode = pca.AlgAES, pca.AlgCBC
	default:
		return nil, err
	}

	IKCert, err := pca.SymmetricDecrypt(alg, mode, recoveredCredential, in.DecryptParam, in.EncryptedCert)
	if err != nil {
		return nil, err
	}
	return IKCert, nil
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
		out0.WriteString(constDMIBIOS)
		out1.WriteString(constDMISYSTEM)
	}
	cmd2 := exec.Command("uname", "-a")
	cmd2.Stdout = &out2
	if err = cmd2.Run(); err != nil {
		return "", err
	}
	ip, _ = entity.GetIP()

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (tpm *TPM) readPcrs(pcrSelection tpm2.PCRSelection) (map[int][]byte, error) {

	numPCRs := len(pcrSelection.PCRs)
	out := map[int][]byte{}

	for i := 0; i < numPCRs; i += 8 {
		// Build a selection structure, specifying 8 PCRs at a time
		end := min(i+8, numPCRs)
		pcrSel := tpm2.PCRSelection{
			Hash: pcrSelection.Hash,
			PCRs: pcrSelection.PCRs[i:end],
		}

		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpm.dev, pcrSel)
		if err != nil {
			log.Printf("ReadPCRs(%+v) failed: %v", pcrSel, err)
			return nil, err
		}

		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			out[pcr] = digest
		}
	}

	if len(out) != numPCRs {
		return nil, errors.New("Failed to read all PCRs")
	}
	return out, nil
}

// createTrustReport collects some information, then returns the TrustReport
func (tpm *TPM) createTrustReport(useHW bool, pcrSelection tpm2.PCRSelection, tRepIn *TrustReportIn) (*TrustReport, error) {
	pcrmp, err := tpm.readPcrs(pcrSelection)
	if err != nil {
		return &TrustReport{}, err
	}

	pcrValues := map[int32]string{}
	for key, pcr := range pcrmp {
		pcrValues[(int32)(key)] = hex.EncodeToString(pcr)
	}

	//we use TrustReportIn as user data of Quote to guarantee its integrity
	attestation, signature, err := tpm2.Quote(tpm.dev, tpm.IK.Handle,
		tpm.IK.Password, emptyPassword, tRepIn.hash(), pcrSelection, tpm2.AlgNull)
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
	manifest, err = getManifest(tpm.config.IMALogPath, tpm.config.BIOSLogPath)
	if err != nil {
		log.Printf("GetManifest Failed, error: %s", err)
	}

	return &TrustReport{pcrinfo, manifest, tRepIn.ClientId, tRepIn.ClientInfo}, nil
}

//GetTrustReport method take a nonce input, generate and return the current trust report
func (tpm *TPM) GetTrustReport(nonce uint64, clientID int64) (*TrustReport, error) {
	clientInfo, err := GetClientInfo(tpm.useHW)
	if err != nil {
		log.Printf("GetClientInfo failed, error : %v \n", err)
	}
	tRepIn := TrustReportIn{
		Nonce:      nonce,
		ClientId:   clientID,
		ClientInfo: clientInfo,
	}
	return tpm.createTrustReport(tpm.useHW, pcrSelectionAll, &tRepIn)
}

// SetDigestAlg method update the Digest alg used to get pcrs and to do the quote.
func (tpm *TPM) SetDigestAlg(alg string) {
	tpm.config.ReportHashAlg = alg
	algIdMap := map[string]tpm2.Algorithm{
		"sha1":   tpm2.AlgSHA1,
		"sha256": tpm2.AlgSHA256,
		"sha384": tpm2.AlgSHA384,
		"sha512": tpm2.AlgSHA512,
	}

	if algID, ok := algIdMap[alg]; ok {
		pcrSelectionAll.Hash = algID
	}
}
