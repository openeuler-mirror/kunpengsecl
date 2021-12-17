package pca

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

//定义几个相关的结构体，用于存放相关信息
var (
	PcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	ParentPassword   = ""
	DefaultPassword  = "\x01\x02\x03\x04"
	DefaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}
)

type IKCertChallenge struct {
	EncryptedCert []byte
	SymKeyParams  SymKeyParams
}

type SymKeyParams struct {
	CredBlob        []byte
	EncryptedSecret []byte
	// the algorithm & scheme used to encrypt the IK Cert
	EncryptAlg string
	// the parameter required by the encrypt algorithm to decrypt the IK Cert
	// if encryptAlg == "AES128-CBC" then it is the IV used to encrypt IK Cert
	// together with the key recovered from credBlob & encryptedSecret
	EncryptParam []byte
}

type TPMAsymKeyParams struct {
	TPMAsymAlgorithm string
	TPMEncscheme     string
}

type Request struct {
	//身份请求
	TPMVer string //TPM版本
	IkPub  *rsa.PublicKey
	IkName []byte //ak名字

}

type IdentitySymKey struct {
	//身份会话密钥内容
	IdentityReq      Request
	TPMAsymmetricKey TPMAsymKeyParams
	SymmetricKey     SymKeyParams
	SymBlob          []byte //用于存放加密后的身份证明
	AsymBlob         []byte //用以存放加密的会话密钥
}

type KeyPub interface {
}
type KeyPri interface {
}
