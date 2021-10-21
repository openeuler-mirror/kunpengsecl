package ractools

import "github.com/google/go-tpm/tpm2"

type Algorithm uint16
type PcrValue string

const EmptyPassword = ""

var (
	// PCR7 is for SecureBoot.
	PcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	PcrSelection1_17 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{1, 17}}
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
	MyPassword = "123456"
	// The initial passwd is 123456, and user can modify it
	// FIXME: we should consider passwd length constraints later
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
)

type PcrInfo struct {
	pcrSelection tpm2.PCRSelection
	pcrValues    map[int]PcrValue
	pcrQuote     []byte
}

type Manifest struct {
	pcr           string
	template_hash string
	format        string
	filedata_hash string
	filename_hint string
}

type TrustReport struct {
	pcrInfo    PcrInfo
	manifest   []Manifest
	clientId   int64
	clientInfo map[string]string
}
