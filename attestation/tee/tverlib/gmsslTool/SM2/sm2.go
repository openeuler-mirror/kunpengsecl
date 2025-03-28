package sm2

/*
#cgo LDFLAGS: -lssl -lcrypto
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <string.h>

// 生成 SM2 密钥对（PEM 格式）
int sm2_generate_keypair(char **pub_key, char **priv_key)
{

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // 设置 SM2 曲线参数
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // 导出公钥和私钥
    BIO *bio_pub = BIO_new(BIO_s_mem());
    BIO *bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, pkey);
    PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL);

    *pub_key = malloc(BIO_pending(bio_pub) + 1);
    *priv_key = malloc(BIO_pending(bio_priv) + 1);
    BIO_read(bio_pub, *pub_key, BIO_pending(bio_pub));
    BIO_read(bio_priv, *priv_key, BIO_pending(bio_priv));
    (*pub_key)[BIO_pending(bio_pub)] = '\0';
    (*priv_key)[BIO_pending(bio_priv)] = '\0';

    BIO_free_all(bio_pub);
    BIO_free_all(bio_priv);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// SM2 签名
int sm2_sign(const char *priv_key_pem, const unsigned char *data, size_t data_len,
             unsigned char *sig, size_t *sig_len) {
    BIO *bio = BIO_new_mem_buf(priv_key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return 0;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sm3(), NULL, pkey) <= 0 ||
        EVP_DigestSignUpdate(ctx, data, data_len) <= 0 ||
        EVP_DigestSignFinal(ctx, sig, sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return 1;
}

// SM2 验签
int sm2_verify(const char *pub_key_pem, const unsigned char *data, size_t data_len,
               const unsigned char *sig, size_t sig_len) {
    BIO *bio = BIO_new_mem_buf(pub_key_pem, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        BIO_free(bio);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return 0;
    }

    int ret = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sm3(), NULL, pkey) > 0 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) > 0 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) > 0) {
        ret = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return ret;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// GenerateSM2KeyPair 生成 SM2 密钥对（返回 PEM 格式字符串）
func GenerateSM2KeyPair() (pubKey, privKey string, err error) {
	var cPub, cPriv *C.char
	if C.sm2_generate_keypair(&cPub, &cPriv) != 1 {
		return "", "", errors.New("failed to generate SM2 key pair")
	}
	defer C.free(unsafe.Pointer(cPub))
	defer C.free(unsafe.Pointer(cPriv))
	return C.GoString(cPub), C.GoString(cPriv), nil
}

// SM2Sign 使用 SM2 私钥签名数据
func SM2Sign(privKeyPEM string, data []byte) ([]byte, error) {
	sig := make([]byte, 64) // SM2 签名长度通常为 64 字节
	var sigLen C.size_t

	if C.sm2_sign(
		C.CString(privKeyPEM),
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		&sigLen,
	) != 1 {
		return nil, errors.New("SM2 signing failed")
	}
	return sig[:sigLen], nil
}

// SM2Verify 使用 SM2 公钥验签
func SM2Verify(pubKeyPEM string, data, sig []byte) (bool, error) {
	ret := C.sm2_verify(
		C.CString(pubKeyPEM),
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)),
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
	)
	if ret == 1 {
		return true, nil
	}
	return false, errors.New("SM2 verification failed")
}
