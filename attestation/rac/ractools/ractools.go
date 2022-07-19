/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: jiayunhao
Create: 2021-09-17
Description: Define the structure for the TPM operation.
*/

package ractools

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
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

	emptyPassword   = ""
	TestImaLogPath  = "./ascii_runtime_measurements"
	TestBiosLogPath = "./binary_bios_measurements"
	TestSeedPath    = "./simulator_seed"
	ImaLogPath      = "/sys/kernel/security/ima/ascii_runtime_measurements"
	BiosLogPath     = "/sys/kernel/security/tpm0/binary_bios_measurements"
	AlgSM3          = 0x0012
	algSHA1Str      = "sha1"
	algSHA256Str    = "sha256"
	algSHA384Str    = "sha384"
	algSHA512Str    = "sha512"
	algSM3Str       = "sm3"
)

type (
	tpm struct {
		config *TPMConfig
		useHW  bool
		dev    io.ReadWriteCloser
		ek     endorsementKey
		ik     attestationKey
	}

	TPMConfig struct {
		IMALogPath    string
		BIOSLogPath   string
		ReportHashAlg string
		SeedPath      string
	}

	endorsementKey struct {
		pub      crypto.PublicKey
		handle   tpmutil.Handle
		alg      string
		password string
	}

	attestationKey struct {
		pub      crypto.PublicKey
		handle   tpmutil.Handle
		alg      string
		password string
		name     []byte
	}

	IKCertInput struct {
		// CredBlob & EncryptedSecret are created by MakeCredential, and will be given as input to ActivateCredential
		CredBlob        []byte // the protected key used to encrypt IK Cert
		EncryptedSecret []byte // the pretected secret related to protection of CredBlob
		EncryptedCert   []byte // the encrypted IK Cert, will be decypted with the key recovered from CredBlob & EncryptedSecret, decrypted Cert will be in PEM format
		DecryptAlg      string // the algorithm & scheme used to decrypt the IK Cert
		DecryptParam    []byte // the parameter required by the decrypt algorithm to decrypt the IK Cert
		// if DecryptAlg == "AES128-CBC" then it is the IV used to decrypt IK Cert together with the key recovered from CredBlob & EncryptedSecret
	}
)

var (
	ErrWrongParams         = errors.New("wrong input parameter")
	ErrFailTPMInit         = errors.New("couldn't start tpm or init key/certificate")
	ErrReadPCRFail         = errors.New("failed to read all PCRs")
	ErrNotSupportedHashAlg = errors.New("the set hash algorithm  is not supported")

	algStrMap = map[tpm2.Algorithm]string{
		tpm2.AlgSHA1:   "SHA1",
		tpm2.AlgSHA256: "SHA256",
		tpm2.AlgSHA384: "SHA384",
		tpm2.AlgSHA512: "SHA512",
	}

	algIdMap = map[string]tpm2.Algorithm{
		algSHA1Str:   tpm2.AlgSHA1,
		algSHA256Str: tpm2.AlgSHA256,
		algSHA384Str: tpm2.AlgSHA384,
		algSHA512Str: tpm2.AlgSHA512,
		algSM3Str:    AlgSM3,
	}

	// PCR7 is for SecureBoot.
	pcrSelectionNil  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}
	pcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	pcrSelection0to7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	pcrSelection7    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	pcrSelectionAll  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
			12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}

	// according to TCG specification, B.3.3  Template L-1: RSA 2048 (Storage)
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf
	EKParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagDecrypt | tpm2.FlagRestricted,

		AuthPolicy: tpmutil.U16Bytes{0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw: tpmutil.U16Bytes{ //256 zeros
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	// according to TCG specification, 7.3.4.2 Template H-1: RSA 2048
	// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf
	IKParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign | tpm2.FlagRestricted,

		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}

	tpmRef *tpm = nil
)

// GetEKPub returns EK public key
func GetEKPub() crypto.PublicKey {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ek.pub
}

// GetIKPub returns IK public key
func GetIKPub() crypto.PublicKey {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ik.pub
}

// GetIKName returns IK name
func GetIKName() []byte {
	if tpmRef == nil {
		return nil
	}
	return tpmRef.ik.name
}

// SetDigestAlg method update the Digest alg used to get pcrs and to do the quote.
func SetDigestAlg(alg string) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}

	if algID, ok := algIdMap[alg]; ok {
		//pcrSelectionNil.Hash = algID
		pcrSelection0.Hash = algID
		pcrSelection0to7.Hash = algID
		pcrSelection7.Hash = algID
		pcrSelectionAll.Hash = algID
		//EKParams.NameAlg = algID
		//IKParams.NameAlg = algID
		//IKParams.RSAParameters.Sign.Hash = algID
		tpmRef.config.ReportHashAlg = alg
		return nil
	}
	return ErrNotSupportedHashAlg

}

// OpenTPM uses either a physical TPM device(default/useHW=true) or a
// simulator(-t/useHW=false), returns a global TPM object variable.
func OpenTPM(useHW bool, conf *TPMConfig, seed int64) error {
	if tpmRef != nil {
		return nil
	}
	if conf == nil {
		return ErrWrongParams
	}
	tpmRef = &tpm{
		config: conf,
		useHW:  useHW,
		dev:    nil,
	}
	SetDigestAlg(conf.ReportHashAlg)
	var err error
	if useHW {
		err = openTpmChip()
	} else {
		err = openTpmSimulator(seed)
	}
	return err
}

// openTpmChip opens TPM hardware chip and reads EC from NVRAM.
// NOTICE:
//   User should use tbprovisioner command tool to write the EC
// into TPM NVRAM before running raagent or the TPM chip already
// has EC in NVRAM when it comes from manufactories.
func openTpmChip() error {
	var err error
	tpmRef.dev, err = tpm2.OpenTPM(tpmDevPath1)
	if err != nil {
		tpmRef.dev, err = tpm2.OpenTPM(tpmDevPath2)
	}
	return err
}

// openTpmSimulator opens TPM simulator.
// EK/IK key and certificate should be loaded/generated from files by config.
func openTpmSimulator(seed int64) error {
	// GetWithFixedSeedInsecure behaves like Get() expect that all of the
	// internal hierarchy seeds are derived from the input seed. So every
	// time we reopen the simulator, we can always get the same ek for the
	// same input.
	var err error
	tpmRef.dev, err = simulator.GetWithFixedSeedInsecure(seed)
	return err
}

// CloseTPM closes an open tpm device and flushes tpm resources.
func CloseTPM() {
	if tpmRef == nil {
		return
	}
	if tpmRef.ek.handle != tpmutil.Handle(0) {
		tpm2.FlushContext(tpmRef.dev, tpmRef.ek.handle)
	}
	if tpmRef.ik.handle != tpmutil.Handle(0) {
		tpm2.FlushContext(tpmRef.dev, tpmRef.ik.handle)
	}
	tpmRef.dev.Close()
	tpmRef = nil
}

// DefineNVRAM defines the index space as size length in the NVRAM
func DefineNVRAM(idx uint32, size uint16) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	attr := tpm2.AttrOwnerWrite | tpm2.AttrOwnerRead |
		tpm2.AttrWriteSTClear | tpm2.AttrReadSTClear
	return tpm2.NVDefineSpace(tpmRef.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
		emptyPassword, emptyPassword, nil, attr, size)
}

// UndefineNVRAM frees the index space in the NVRAM
func UndefineNVRAM(idx uint32) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	return tpm2.NVUndefineSpace(tpmRef.dev, emptyPassword, tpm2.HandleOwner,
		tpmutil.Handle(idx))
}

// WriteNVRAM writes the data at index into the NVRAM
func WriteNVRAM(idx uint32, data []byte) error {
	if tpmRef == nil {
		return ErrFailTPMInit
	}
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
		err := tpm2.NVWrite(tpmRef.dev, tpm2.HandleOwner, tpmutil.Handle(idx),
			emptyPassword, data[offset:end], offset)
		if err != nil {
			return err
		}
		offset = end
	}
	return nil
}

// ReadNVRAM reads the data at index from the NVRAM
func ReadNVRAM(idx uint32) ([]byte, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	return tpm2.NVReadEx(tpmRef.dev, tpmutil.Handle(idx),
		tpm2.HandleOwner, emptyPassword, 0)
}

// GenerateEKey generates the ek key by tpm2, gets the handle and public part
func GenerateEKey() error {
	var err error
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	// for TPM chip, maybe need to load EKParams from NVRAM to create the
	// same EK as the saved EC in NVRAM, need to test!!!
	tpmRef.ek.handle, tpmRef.ek.pub, err = tpm2.CreatePrimary(tpmRef.dev,
		tpm2.HandleEndorsement, pcrSelectionNil,
		emptyPassword, emptyPassword, EKParams)
	if err != nil {
		tpmRef.ek.handle = tpmutil.Handle(0)
		tpmRef.ek.pub = nil
		return err
	}
	return nil
}

// GenerateIKey generates the ik key as a primary key by tpm2, gets the handle, public
// and name fields to use later
func GenerateIKey() error {
	var err error
	if tpmRef == nil {
		return ErrFailTPMInit
	}
	tpmRef.ik.handle, tpmRef.ik.pub, err = tpm2.CreatePrimary(tpmRef.dev,
		tpm2.HandleEndorsement, pcrSelectionNil,
		emptyPassword, emptyPassword, IKParams)
	if err != nil {
		tpmRef.ik.handle = tpmutil.Handle(0)
		tpmRef.ik.pub = nil
		return err
	}
	_, ikName, _, err := tpm2.ReadPublic(tpmRef.dev, tpmRef.ik.handle)
	if err != nil {
		return err
	}
	tpmRef.ik.password = emptyPassword
	tpmRef.ik.name = ikName
	return nil
}

// ActivateIKCert decrypts the IkCert from the input, and return it in PEM format
func ActivateIKCert(in *IKCertInput) ([]byte, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	sessHandle, _, err := tpm2.StartAuthSession(tpmRef.dev, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 16),
		nil, tpm2.SessionPolicy, tpm2.AlgNull, tpm2.AlgSHA256)
	if err != nil {
		return nil, errors.New("StartAuthSession() failed, error:" + err.Error())
	}
	defer tpm2.FlushContext(tpmRef.dev, sessHandle)

	if _, err = tpm2.PolicySecret(tpmRef.dev, tpm2.HandleEndorsement,
		tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		sessHandle, nil, nil, nil, 0); err != nil {
		return nil, errors.New("PolicySecret() failed, error:" + err.Error())
	}

	recoveredCredential, err := tpm2.ActivateCredentialUsingAuth(tpmRef.dev, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(emptyPassword)},
		{Session: sessHandle, Attributes: tpm2.AttrContinueSession, Auth: []byte(emptyPassword)},
	}, tpmRef.ik.handle, tpmRef.ek.handle, in.CredBlob, in.EncryptedSecret)
	if err != nil {
		return nil, errors.New("ActivateCredentialWithAuth error:" + err.Error())
	}
	var alg, mode uint16
	switch in.DecryptAlg {
	case cryptotools.Encrypt_Alg: //AES128_CBC
		alg, mode = cryptotools.AlgAES, cryptotools.AlgCBC
	default:
		return nil, err
	}
	IKCert, err := cryptotools.SymmetricDecrypt(alg, mode,
		recoveredCredential, in.DecryptParam, in.EncryptedCert)
	if err != nil {
		return nil, err
	}
	return IKCert, nil
}

// GetClientInfo returns json format client information.
// TODO: add some other information
func GetClientInfo() (string, error) {
	var err error
	var out0 bytes.Buffer
	var out1 bytes.Buffer
	var out2 bytes.Buffer
	if tpmRef == nil {
		return "", ErrFailTPMInit
	}
	if tpmRef.useHW {
		// execute dmidecode shell-commands to acquire information
		// remind: need sudo permission
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
	clientInfo := map[string]string{}
	start0 := strings.Index(out0.String(), "BIOS Information")
	start1 := strings.Index(out1.String(), "System Information")
	clientInfo["bios"] = out0.String()[start0:]
	clientInfo["system"] = out1.String()[start1:]
	clientInfo["os"] = out2.String()
	clientInfo["ip"] = typdefs.GetIP()
	clientInfo["version"] = "1.0.0"
	strCI, err := json.Marshal(clientInfo)
	return string(strCI), err
}

func readPcrLog(pcrSelection tpm2.PCRSelection) ([]byte, error) {
	var buf bytes.Buffer
	var digBuf []byte
	switch pcrSelection.Hash {
	case tpm2.AlgSHA1:
		digBuf = make([]byte, typdefs.Sha1DigestLen*2)
	case tpm2.AlgSHA256:
		digBuf = make([]byte, typdefs.Sha256DigestLen*2)
	// TODO: need rewrite
	case AlgSM3:
		digBuf = make([]byte, typdefs.SM3DigestLen*2)
	}
	numPCRs := len(pcrSelection.PCRs)
	// read pcr one by one by ordering
	for i := 0; i < numPCRs; i++ {
		pcrSel := tpm2.PCRSelection{
			Hash: pcrSelection.Hash,
			PCRs: []int{i},
		}
		// Ask the TPM for those PCR values.
		ret, err := tpm2.ReadPCRs(tpmRef.dev, pcrSel)
		if err != nil {
			return nil, err
		}
		// Keep track of the PCRs we were actually given.
		for pcr, digest := range ret {
			hex.Encode(digBuf, digest)
			buf.Write(digBuf)
			switch pcrSelection.Hash {
			case tpm2.AlgSHA1:
				buf.WriteString(fmt.Sprintf(" sha1 %02d\n", pcr))
			case tpm2.AlgSHA256:
				buf.WriteString(fmt.Sprintf(" sha256 %02d\n", pcr))
			}
		}
	}
	return buf.Bytes(), nil
}

// GetTrustReport takes a nonce input, generates the current trust report
func GetTrustReport(clientID int64, nonce uint64, algStr string) (*typdefs.TrustReport, error) {
	if tpmRef == nil {
		return nil, ErrFailTPMInit
	}
	clientInfo, err := GetClientInfo()
	if err != nil {
		return nil, err
	}
	tRepIn := typdefs.TrustReportInput{
		ClientID:   clientID,
		Nonce:      nonce,
		ClientInfo: clientInfo,
	}
	//we use TrustReportIn as user data of Quote to guarantee its integrity
	repHash, err := tRepIn.Hash(algStr)
	if err != nil {
		return nil, err
	}
	quoted, signature, err := tpm2.Quote(tpmRef.dev,
		tpmRef.ik.handle, tpmRef.ik.password, emptyPassword,
		repHash, pcrSelectionAll, tpm2.AlgNull)
	if err != nil {
		return nil, err
	}
	jsonSignature, err := json.Marshal(signature)
	if err != nil {
		return nil, err
	}
	pcrLog, err := readPcrLog(pcrSelectionAll)
	if err != nil {
		return nil, err
	}
	biosLog, err := ioutil.ReadFile(tpmRef.config.BIOSLogPath)
	if err != nil {
		return nil, err
	}
	imaLog, err := ioutil.ReadFile(tpmRef.config.IMALogPath)
	if err != nil {
		return nil, err
	}
	report := typdefs.TrustReport{
		ClientID:   tRepIn.ClientID,
		Nonce:      tRepIn.Nonce,
		ClientInfo: tRepIn.ClientInfo,
		Quoted:     quoted,
		Signature:  jsonSignature,
		Manifests: []typdefs.Manifest{
			{Key: typdefs.StrPcr, Value: pcrLog},
			{Key: typdefs.StrBios, Value: biosLog},
			{Key: typdefs.StrIma, Value: imaLog},
		},
	}
	return &report, nil
}
