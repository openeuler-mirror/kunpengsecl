package pca

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

//定义几个相关的结构体，用于存放相关信息
//
var (
	PcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	ParentPassword   = " "
	DefaultPassword  = "\x01\x02\x03\x04"
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
)

type ToACandSymKey struct {
	Credential      []byte
	TPMSymKeyParams TPMSymKeyParams
	SymBlob         []byte
}
type TPMSymKeyParams struct {
	//可能还要存放加密的算法等参数
	TPMSymAlgorithm string
	TPMEncscheme    string

	EncryptAC []byte
	IV        []byte
}
type TPMAsymKeyParams struct {
	TPMAsymAlgorithm string
	TPMEncscheme     string
}
type Request struct {
	//身份请求
	TPMVer string //TPM版本
	AkPub  *rsa.PublicKey
	AkName []byte //ak名字

}
type IdentitySymKey struct {
	//身份会话密钥内容
	IdentityReq      Request
	TPMAsymmetricKey TPMAsymKeyParams
	TPMSymmetricKey  TPMSymKeyParams
	SymBlob          []byte //用于存放加密后的身份证明
	AsymBlob         []byte //用以存放加密的会话密钥
}

type KeyPub interface {
}
type KeyPri interface {
}
