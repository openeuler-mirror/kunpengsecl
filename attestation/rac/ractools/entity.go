package ractools

import (
	"crypto"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type Algorithm uint16
type PcrValue string

const EmptyPassword = ""

var (
	// PCR7 is for SecureBoot.
	PcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	PcrSelection0to7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	PcrSelection7    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	PcrSelectionAll  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}
	Params = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault | tpm2.FlagNoDA,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
	DefaultKeyParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 1<<16 + 1,
		},
	}
	MyPcrSelection         = PcrSelection7
	DefaultRsaSignerParams = tpm2.Public{
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
	ekidx tpmutil.Handle = 0x01c0000a
)

type (
	TPM struct { //还需讨论
		config TPMConfig
		dev    io.ReadWriteCloser
	}

	TPMConfig struct { //还需讨论
		IMALogPath    string
		BIOSLogPath   string
		ReportHashAlg string
		IK            *AttestationKey
		EK            *EndorsementKey
		isPhysicalTpm bool
	}

	EndorsementKey struct {
		Alg      string
		Pub      crypto.PublicKey
		Handle   tpmutil.Handle
		Password string
	}

	AttestationKey struct {
		Name     []byte
		Public   []byte
		Private  []byte
		Handle   tpmutil.Handle
		Password string
		PcrSel   tpm2.PCRSelection
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
