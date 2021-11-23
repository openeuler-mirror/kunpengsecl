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
const (
	CertPEM = `
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIIFrl/kXlBImAwDQYJKoZIhvcNAQELBQAwNTEOMAwGA1UE
BhMFQ2hpbmExETAPBgNVBAoTCENvbW1wYW55MRAwDgYDVQQDEwdSb290IENBMB4X
DTIxMTEyMTA3MzYzMloXDTIyMTEyMTA3MzY0MlowNzEOMAwGA1UEBhMFQ2hpbmEx
EDAOBgNVBAoTB0NvbXBhbnkxEzARBgNVBAMTCnByaXZhY3kgY2EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOehd7S3PTsW+LfswbiIDRYegYk/cDiBGF
CrjHTLs35SKRYKzfS0GiMdnPhveZk/qKstQu/JeIhn9ycSBx3739v3F0ySqZQTMX
/24QWBp4cq4UlQkWa+Q/GdgXj/9OokhWeWo8aJHJVbHsMprPQ15wfleNfcYEGUYa
5Aho1finlXE/HGpfka+FQNQocO0ZqmXR6XJbMBk+3SEuWiS1jfFtFYk1POkc+Jw3
syN/foOWfH5UqV0crcxMAAbqDW2j6vyqkFfDJD1GraCm/vGySzlFpmRjTOj90K9P
wTeGzO1qLgi7OKWkiJcXfiQSjt1NDCozp1cIdCl2IP1JCZIxs+gNAgMBAAGjgY0w
gYowDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB
/wQIMAYBAf8CAQEwHQYDVR0OBBYEFHGWXhHCb0M/3712y+CSny2u3hflMB8GA1Ud
IwQYMBaAFJLKF+6Wwgf9998CBOph5bg5tKkXMA8GA1UdEQQIMAaHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAGIoIubJJyq85rNI9f+SF4TDybbdnsMnrcAt98t2fPsW
Vp2s0RYCwu5OSZDrqiiErLXlX7frgvpeEuiWU/K+ruEM6Fj3sirCUd6G2QYYHboC
eRRaEvAW7OkKnUW35dROZRaZuJ7t5+TfnCBiuxhNRutBAvnGavOX25B/k7dp6F3V
f/sJaXblpvQ8RTi4YUgkLFxUGHDmMYiDFCaqJn2hgRb1UNibshx4xMOsO8jMh7xT
zNcyYs8zM4V6wOk3T+lU/GnH4FdJQ4xKxZTqkVz3+qeq/1cl/G8PJttWM+yARTpj
8PPjY/QIa7VcWEUj9DeREBbqJFcyc5JvhOScYw4EMPQ=
-----END CERTIFICATE-----`
	PubPEM = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`
)

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
