package sm3

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <openssl/evp.h>
#include <string.h>

// SM3 哈希计算
void sm3_hash(const unsigned char *data, size_t data_len, unsigned char *hash) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sm3();
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// SM3Hash 计算数据的 SM3 哈希值（固定 32 字节）
func SM3Hash(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("input data cannot be empty")
	}

	hash := make([]byte, 32) // SM3 输出长度为 32 字节
	C.sm3_hash(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&hash[0])),
	)
	return hash, nil
}