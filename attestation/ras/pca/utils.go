package pca

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/pkg/errors"
)

const (
	Tpm_ID_SHA256 = 0x00B
	Tpm_Sym_CBC   = 255
	Tpm_AES       = 0x6
)

//对加密等的操作
func CBCEncrypt(payload, iv []byte, block cipher.Block) ([]byte, error) {
	//通过block和iv使用CBC加密方式对payload进行加密
	//通过调用NewCBCEncrypter返回一个大小与iv相同的加密模式
	blockMode := cipher.NewCBCEncrypter(block, iv)
	paddspare := block.BlockSize() - len(payload)%block.BlockSize()
	paddtext := bytes.Repeat([]byte{byte(paddspare)}, paddspare)
	withPadding := append(payload, paddtext...)
	encryptByte := make([]byte, len(withPadding))
	blockMode.CryptBlocks(encryptByte, withPadding)
	return encryptByte, nil
}

// Encrypt the payload with given key, iv & encScheme
func SymetricEncrypt(payload, key, iv []byte, algorithm, encScheme string) ([]byte, error) {
	//payload是需要加密的数据，key和iv是两个加密的参数，
	//encScheme是加密策略，algorithm是加密算法
	//日志
	//先判断格式数据是否正确
	if len(payload) == 0 || len(key) == 0 || len(iv) == 0 {
		return nil, errors.New("payload or key or iv may be a nil")
	}
	//通过算法进行相应的加密
	if algorithm == TPM_AES {
		cipherblock, err := aes.NewCipher(key)
		if err != nil {
			return nil, errors.New("NewCipher returns error!")
		}
		switch encScheme {
		case TPM_CBC:
			return CBCEncrypt(payload, iv, cipherblock)
		default:
			return nil, errors.New("Unsupported symetric encryption scheme in SymetricEncrypt()")
		}
	}
	return nil, nil
}

//对非对称解密
//privKey 表示私钥，encScheme表示加密方案
func AsymDecrypt(privKey crypto.PrivateKey, encScheme string, blob []byte, label []byte) ([]byte, error) {
	//使用私钥privKey 在encsheme方案下对blob进行解密
	if encScheme == "SHA256" { // encScheme might be "OAEP"?
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey.(*rsa.PrivateKey), blob, label)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privKey.(*rsa.PrivateKey), blob)
}

//生成长度是length的 byte类型的随机数
//随机函数的生成：CreateRandomByte
func CreateRandomBytes(len int) ([]byte, error) {
	//参数为生成的随机数的长度（字节），返回值为这个随机数
	b := make([]byte, len)
	_, err := rand.Read(b) //调用Read函数
	if err != nil {
		return nil, err
	}
	return b, nil
}
