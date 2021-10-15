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
	"io"
)

const(
	Tpm_ID_SHA256		=0x00B
	Tpm_Sym_CBC			=255
	Tpm_AES				=0x6

)
//对加密等的操作
func SymetricByCBCEncrypt(pay,iv []byte,block cipher.Block)([]byte,error){
	//通过block和iv使用CBC加密方式对pay进行加密
	//通过调用NewCBCEncrypter返回一个大小与iv相同的加密模式
	blockMode :=cipher.NewCBCEncrypter(block,iv)
	paddspare :=block.BlockSize() - len(pay)%block.BlockSize()
	paddtext := bytes.Repeat([]byte{byte(paddspare)},paddspare)
	withPadding :=append(pay,paddtext...)
	encryptByte := make([]byte,len(withPadding))
	blockMode.CryptBlocks(encryptByte,withPadding)
	return encryptByte, nil
}
//make the payload encrypt by key and iv with something
func SymetricEncrypt(symblob ,key ,iv []byte,algorithm ,encScheme string)([]byte,error){
	//pay是需要加密的数据，key和iv是两个加密的参数，
	//encScheme是加密策略，algorithm是加密算法
	//日志
	//先判断格式数据是否正确
	if len(symblob)==0||len(key)==0||len(iv)==0{
		return nil,errors.New("pay or key or iv may be a nil")
	}
	//通过算法进行相应的加密
	if algorithm ==TPM_AES{
		cipherblock,err := aes.NewCipher(key)
		if err!=nil{
			return nil,errors.New("NewCipher is Error!")
		}
		switch encScheme {
		case TPM_CBC:
			return SymetricByCBCEncrypt(symblob,iv,cipherblock)
		default:
			return nil, errors.New("SymetricEncrypt() Unsupported the sym algorithm scheme")
		}
	}
	return nil, nil
}
//TPM2下对非对称解密
//prikey 表示私钥，enscheme表示加密方案
func AsymDecryptofTPM(priKey crypto.PrivateKey,encScheme string,blob []byte,label []byte)([]byte,error){
	//使用私钥priKey 在encsheme方案下对blob进行解密
	if encScheme == "SHA256"{
		var rng io.Reader
		decryptedBlobBytes,err := rsa.DecryptOAEP(sha256.New(),rng,priKey.(*rsa.PrivateKey),blob,label)
		if err!=nil{

		}
		return decryptedBlobBytes,nil
	}
		return rsa.DecryptPKCS1v15(rand.Reader,priKey.(*rsa.PrivateKey),blob)
}
//生成长度是length的 byte类型的随机数
//随机函数的生成：CreateRandomByte
func CreateRandomByte(len int)([]byte,error){
	//参数为生成的随机数的长度（字节），返回值为这个随机数
	b := make([]byte,len)
	_,err := rand.Read(b)   //调用Read函数
	if err!=nil{
		return nil,err
	}
	return b,nil
}