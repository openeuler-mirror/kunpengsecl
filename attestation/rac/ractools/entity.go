/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
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
	"crypto"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type Algorithm uint16
type PcrValue string

const (
	emptyPassword   = ""
	TestImaLogPath  = "./ascii_runtime_measurements"
	TestBiosLogPath = "./binary_bios_measurements"
	ImaLogPath      = "/sys/kernel/security/ima/ascii_runtime_measurements"
	BiosLogPath     = "/sys/kernel/security/tpm0/binary_bios_measurements"
)

var (
	// PCR7 is for SecureBoot.
	pcrSelectionNil  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}
	pcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	pcrSelection0to7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	pcrSelection7    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	pcrSelectionAll  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}
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
	defaultRsaSignerParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

type (
	TPM struct {
		config *TPMConfig
		useHW  bool
		dev    io.ReadWriteCloser
		EK     EndorsementKey
		IK     AttestationKey
	}

	TPMConfig struct {
		IMALogPath    string
		BIOSLogPath   string
		ReportHashAlg string
	}

	EndorsementKey struct {
		Alg      string
		Pub      crypto.PublicKey
		Handle   tpmutil.Handle
		Password string
	}

	AttestationKey struct {
		Name     []byte
		Pub      crypto.PublicKey
		Handle   tpmutil.Handle
		Password string
		Alg      string
	}

	PcrInfo struct {
		AlgName string
		Values  map[int32]string
		Quote   PcrQuote
	}

	PcrQuote struct {
		Quoted    []byte
		Signature []byte
	}

	Manifest struct {
		Type    string //"bios", "ima"
		Content []byte //content fetched from securityfs bios measurement & ima measurement file interfaces
	}

	TrustReport struct {
		PcrInfo    PcrInfo
		Manifest   []Manifest
		ClientID   int64
		ClientInfo string
	}

	TrustReportIn struct {
		Nonce      uint64
		ClientId   int64
		ClientInfo string
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
