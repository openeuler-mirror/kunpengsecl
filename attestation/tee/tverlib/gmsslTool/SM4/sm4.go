package sm4

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

// 加密函数
void sm4_encrypt(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return;
    }

    // 初始化加密操作，启用填充
    if(1 != EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // 提供要加密的数据并进行加密
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *ciphertext_len = len;

    // 完成加密操作
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *ciphertext_len += len;

    // 清理上下文
    EVP_CIPHER_CTX_free(ctx);
}

// 解密函数
void sm4_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, const unsigned char *iv,
                 unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    // 创建并初始化上下文
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return;
    }

    // 初始化解密操作，启用填充
    if(1 != EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // 提供要解密的数据并进行解密
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *plaintext_len = len;

    // 完成解密操作
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    *plaintext_len += len;

    // 清理上下文
    EVP_CIPHER_CTX_free(ctx);
}
*/
import "C"
import (
	"crypto/rand"
	"errors"
	"unsafe"
)
const SM4KeySize = 16
const SM4IVSize = 16
// SM4Encrypt 使用 SM4 算法进行加密
func SM4Encrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	if len(key) != SM4KeySize {
		return nil, nil, errors.New("SM4 key must be 16 bytes")
	}
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}
    const IVSize = 16
	ciphertext := make([]byte, len(plaintext)+IVSize)
	var ciphertextLen C.int
	C.sm4_encrypt(
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		C.int(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		&ciphertextLen,
	)
	return ciphertext[:ciphertextLen], iv, nil
}

// SM4Decrypt 使用 SM4 算法进行解密
func SM4Decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	
    if len(key) != SM4KeySize {
		return nil, errors.New("SM4 key must be 16 bytes")
	}
	if len(iv) != SM4IVSize {
		return nil, errors.New("SM4 IV must be 16 bytes")
	}
	plaintext := make([]byte, len(ciphertext))
	var plaintextLen C.int
	C.sm4_decrypt(
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.int(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&iv[0])),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		&plaintextLen,
	)
	return plaintext[:plaintextLen], nil
}
