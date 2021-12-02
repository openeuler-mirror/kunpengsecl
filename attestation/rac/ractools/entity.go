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
	"crypto"
	"io"

	"github.com/google/go-tpm/tpm2"
)

type Algorithm uint16
type PcrValue string

const (
	emptyPassword = ""
	ekPemTest     = `
-----BEGIN CERTIFICATE-----
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
)

var (
	// PCR7 is for SecureBoot.
	pcrSelectionNil  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{}}
	pcrSelection0    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	pcrSelection0to7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7}}
	pcrSelection7    = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
	pcrSelectionAll  = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}
	params = tpm2.Public{
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
	defaultKeyParams = tpm2.Public{
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
	TPM struct { //还需讨论
		config TPMConfig
		dev    io.ReadWriteCloser
	}

	TPMConfig struct { //还需讨论
		IMALogPath      string
		BIOSLogPath     string
		ReportHashAlg   string
		IK              *AttestationKey
		EK              *EndorsementKey
		useHW           bool
		IsUseTestEKCert bool //If true, use ek test case. Not used by default
	}

	EndorsementKey struct {
		Alg      string
		Pub      crypto.PublicKey
		Handle   uint32
		Password string
	}

	AttestationKey struct {
		Name     []byte
		Public   []byte
		Private  []byte
		Pub      crypto.PublicKey
		Handle   uint32
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
