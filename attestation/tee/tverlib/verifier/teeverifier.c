/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

#include "teeverifier.h"
#include "common.h"
#include "pair_FP512BN.h"
#include <cjson/cJSON.h>
#include <openssl/evp.h>

#define _SHA256(d, n, md)          \
    {                              \
        SHA256_CTX ctx;            \
        SHA256_Init(&ctx);         \
        SHA256_Update(&ctx, d, n); \
        SHA256_Final(md, &ctx);    \
    }

#define _SHA512(d, n, md)          \
    {                              \
        SHA512_CTX ctx;            \
        SHA512_Init(&ctx);         \
        SHA512_Update(&ctx, d, n); \
        SHA512_Final(md, &ctx);    \
    }

#define HW_IT_PRODUCT_CA_CERT_PATH "./Huawei IT Product CA.pem"
#define TAS_ROOT_CERT_PATH "TAS Root Cert.pem"

#define verifier_error(msg)  \
    {                        \
        printf("%s\n", msg); \
        return NULL;         \
    }

#define file_error(msg)                          \
    {                                            \
        printf("Couldn't open file: %s\n", msg); \
        return NULL;                             \
    }

// static void free_report(TA_report *report);

// base64 encode url
void base64urlencode(const uint8_t *src, int src_len, uint8_t *cipher, int *dest_len)
{
    int cipLen = EVP_EncodeBlock((unsigned char *)cipher, (const unsigned char *)src, src_len);
    // change "+" to "-", "/" to "_", remove "=".
    for (int i = cipLen - 1; i >= 0; i--) {
        if (*(cipher + i) == '+')
            *(cipher + i) = '-';
        else if (*(cipher + i) == '/')
            *(cipher + i) = '_';
        else if (*(cipher + i) == '=')
            //*(cipher + i) = *(cipher + i + 1);
            cipLen--;
    }
    *dest_len = cipLen;
    // tlogd("%s", cipher);
    return;
}

// base64 decode url
uint8_t *base64urldecode(const uint8_t *src, int src_len, int *dest_len)
{
    // change "-" to "+", "_" to "/", add back "=".
    size_t i = 0;
    char *tail1 = "=";
    char *tail2 = "==";
    uint8_t *b64 = malloc(sizeof(uint8_t) * (src_len + 3));
    // int dest_len = 0;
    memcpy(b64, src, src_len);
    for (i = 0; i < src_len; i++) {
        if (*(b64 + i) == '-')
            *(b64 + i) = '+';
        else if (*(b64 + i) == '_')
            *(b64 + i) = '/';
    }
    *(b64 + i) = '\0';
    if (src_len % 4 == 2) {
        strcat(b64, tail2);
        *dest_len = (src_len + 2) / 4 * 3 - 2;
    } else if (src_len % 4 == 3) {
        strcat(b64, tail1);
        *dest_len = (src_len + 1) / 4 * 3 - 1;
    } else if (src_len % 4 == 0)
        *dest_len = src_len / 4 * 3;

    uint8_t *plain = (uint8_t *)malloc(sizeof(uint8_t) * (*dest_len + 6));
    int cipLen = EVP_DecodeBlock((unsigned char *)plain, (const unsigned char *)b64, strlen(b64));
    free(b64);
    return plain;
}

void uint82str(const uint8_t *source, int source_len, char *dest)
{
    for (int32_t i = 0; i < source_len; i++) {
        if ((source[i] >> 4) <= 9) // 0x39 corresponds to the character '9'
            dest[2 * i] = (source[i] >> 4) + 0x30;
        else // Otherwise, it is a letter, and 7 symbols need to be skipped
            dest[2 * i] = (source[i] >> 4) + 0x37;
        if ((source[i] % 16) <= 9)
            dest[2 * i + 1] = (source[i] % 16) + 0x30;
        else
            dest[2 * i + 1] = (source[i] % 16) + 0x37;
    }
}

void str2uint8(const char *source, int dest_len, uint8_t *dest)
{
    uint8_t HighByte;
    uint8_t LowByte;

    for (int i = 0; i < dest_len; i++) {
        HighByte = toupper(source[i * 2]);
        LowByte = toupper(source[i * 2 + 1]);
        if (HighByte <= 0x39)
            HighByte -= 0x30;
        else
            HighByte -= 0x37;
        if (LowByte <= 0x39)
            LowByte -= 0x30;
        else
            LowByte -= 0x37;
        dest[i] = (HighByte << 4) | LowByte;
    }
}

// base64 decode for akpub after xxx
bool decodeAKPubKey(cJSON *in, buffer_data *out)
{
    if (in == NULL) {
        printf("akpub is null");
        return false;
    }
    cJSON *ktyjson = cJSON_GetObjectItemCaseSensitive(in, "kty");
    if (strcmp(ktyjson->valuestring, "RSA") == 0) {
        cJSON *njson = cJSON_GetObjectItemCaseSensitive(in, "n");
        // njson needs urlbase64 decode!!!!
        uint8_t *tmp1 = (uint8_t *)njson->valuestring;
        out->buf = base64urldecode(tmp1, strlen(tmp1), &out->size);
    } else if (strcmp(ktyjson->valuestring, "DAA") == 0) {
        cJSON *qsjson = cJSON_GetObjectItemCaseSensitive(in, "qs");
        // qsjson needs urlbase64 decode!!!!
        uint8_t *tmp2 = (uint8_t *)qsjson->valuestring;
        out->buf = base64urldecode(tmp2, strlen(tmp2), &out->size);
    } else {
        printf("key type error!");
        return false;
    }

    return true;
}

EVP_PKEY *buildPubKeyFromModulus(buffer_data *pub)
{
    EVP_PKEY *key = NULL;
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    RSA *rsapub = RSA_new();
    if (NULL == e || NULL == n || NULL == rsapub)
        goto err;

    key = EVP_PKEY_new();
    if (NULL == key)
        goto err;

    BN_set_word(e, 0x10001);
    BN_bin2bn(pub->buf, pub->size, n);

    RSA_set0_key(rsapub, n, e, NULL);
    EVP_PKEY_set1_RSA(key, rsapub);
    RSA_free(rsapub);
    return key;
err:
    RSA_free(rsapub);
    BN_free(n);
    BN_free(e);
    return NULL;
}

static bool verifyCertByCert(buffer_data *cert, uint8_t *root_cert_pathname)
{
    X509 *a = NULL;
    EVP_PKEY *r = NULL;
    BIO *bp = NULL;
    bool res = false;
    buffer_data root_cert = {0, NULL};
    size_t size = 0;
    if (NULL == (root_cert.buf = file_to_buffer(root_cert_pathname, &size))) {
        goto err;
    }
    root_cert.size = (uint32_t)size;

    if (NULL == (r = getPubKeyFromCert(&root_cert, NULL))) {
        goto err;
    }

    if (NULL == (bp = BIO_new_mem_buf(cert->buf, cert->size))) {
        goto err;
    }

    if (NULL == (a = PEM_read_bio_X509(bp, NULL, NULL, NULL))) {
        printf("failed to get drkcert x509\n");
        goto err;
    }

    if (1 != X509_verify(a, r)) {
        goto err;
    }

    res = true;
err:
    X509_free(a);
    BIO_vfree(bp);
    EVP_PKEY_free(r);
    if (root_cert.buf != NULL)
        free(root_cert.buf);

    return res;
}

// scenario: no as, parse akcert to get pubkey
EVP_PKEY *getPubKeyFromDrkIssuedCert(buffer_data *cert)
{
    buffer_data datadrk, signdrk, certdrk, akpub;
    bool rt;
    EVP_PKEY *key = NULL;

    rt = getDataFromAkCert(cert, &datadrk, &signdrk, &certdrk, &akpub);
    if (!rt) {
        printf("get NOAS data is failed!\n");
        goto err;
        // return false;
    }

    // verify the integrity of data in drk issued cert
    rt = verifysig_x509cert(&datadrk, &signdrk, &certdrk, HW_IT_PRODUCT_CA_CERT_PATH);
    if (!rt) {
        printf("validate drk signed ak cert failed!\n");
        goto err;
        // return NULL;
    }

    // build a pub key with the modulus carried in drk issued cert
    key = buildPubKeyFromModulus(&akpub);

err:
    if (datadrk.buf != NULL)
        free(datadrk.buf);
    if (signdrk.buf != NULL)
        free(signdrk.buf);
    if (certdrk.buf != NULL)
        free(certdrk.buf);
    if (akpub.buf != NULL)
        free(akpub.buf);
    return key;
}

bool verifySigByKey(buffer_data *mhash, buffer_data *sign, EVP_PKEY *key)
{
    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        printf("the pub key type is not in supported type list(rsa)\n");
        return false;
    }

    uint8_t buf[512] = {0};
    int rt = RSA_public_decrypt(sign->size, sign->buf, buf, EVP_PKEY_get1_RSA(key), RSA_NO_PADDING);
    if (rt == -1) {
        printf("RSA public decrypt is failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    // rt = RSA_verify_PKCS1_PSS_mgf1(EVP_PKEY_get1_RSA(key), mhash->buf,
    // EVP_sha256(), EVP_sha256(), buf, -2);
    rt = RSA_verify_PKCS1_PSS(EVP_PKEY_get1_RSA(key), mhash->buf, EVP_sha256(), buf, -2);
    // rt = RSA_verify(EVP_PKEY_RSA_PSS, mhash->buf, SHA256_DIGEST_LENGTH,
    // signdrk.buf, signdrk.size, EVP_PKEY_get1_RSA(key));
    if (rt != 1) {
        printf("verify sign is failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
        return false;
    }

    return true;
}

EVP_PKEY *getPubKeyFromCert(buffer_data *cert, char *root_cert_pathname)
{
    EVP_PKEY *key = NULL;
    X509 *c = NULL;

    if (NULL != root_cert_pathname && !verifyCertByCert(cert, root_cert_pathname)) {
        printf("WARNING: failed to verify x509 cert\n");
    }

    BIO *bp = BIO_new_mem_buf(cert->buf, cert->size);
    if (NULL == bp)
        return NULL;

    c = PEM_read_bio_X509(bp, NULL, NULL, NULL);
    BIO_vfree(bp);
    if (c == NULL) {
        printf("failed to get x509 cert\n");
        return NULL;
    }

    key = X509_get_pubkey(c);
    X509_free(c);
    if (key == NULL) {
        printf("Error getting public key from certificate\n");
    }

    return key;
}

static bool verifydatasig_bykey(buffer_data *data, buffer_data *sign, EVP_PKEY *key)
{
    // caculate the digest of the data
    uint8_t digest[SHA256_DIGEST_LENGTH];
    _SHA256(data->buf, data->size, digest);

    // perform signature verification
    buffer_data mhash = {sizeof(digest), digest};
    bool rt = verifySigByKey(&mhash, sign, key);

    return rt;
}

// scenario: no as
static bool verifysig_drksignedcert(buffer_data *data, buffer_data *sign, buffer_data *cert)
{
    // get the key for signature verification
    EVP_PKEY *key = getPubKeyFromDrkIssuedCert(cert);
    if (key == NULL)
        return false;

    bool rt = verifydatasig_bykey(data, sign, key);
    EVP_PKEY_free(key);

    return rt;
}

static void trim_ending_0(uint8_t *buf, int *size)
{
    for (; *size > 0 && buf[*size - 1] == 0; (*size)--)
        ;
}

// scenario: as no daa
static bool verifysig_x509cert(buffer_data *data, buffer_data *sign, buffer_data *cert, char *root_cert_pathname)
{
    // get the key for signature verification
    EVP_PKEY *key = getPubKeyFromCert(cert, root_cert_pathname);
    if (key == NULL)
        return false;

    bool rt = verifydatasig_bykey(data, sign, key);
    EVP_PKEY_free(key);

    return rt;
}

// file format of daa issuer pubkey, in HEX strings:
// [X.x0]\n
// [X.x1]\n
// [X.y0]\n
// [X.y1]\n
// [Y.x0]\n
// [Y.x1]\n
// [Y.y0]\n
// [Y.y1]\n
char *DEFAULT_DAA_ISSUER_PUBKEY_FILE = "./daa-pubkey";

typedef struct {
    ECP_FP512BN *a;
    ECP_FP512BN *b;
    ECP_FP512BN *c;
    ECP_FP512BN *d;
} daa_ak_cert;

typedef struct {
    BIG_512_60 h2;
    BIG_512_60 s;
    BIG_512_60 nm;
    ECP_FP512BN *j;
    ECP_FP512BN *k;
} daa_signature;

typedef struct {
    ECP2_FP512BN *x;
    ECP2_FP512BN *y;
} daa_pub;

static int hex2bin_append(const char *hexbuf, size_t *offset, size_t buflen, octet *oct)
{
    char *p = strchr(hexbuf + *offset, '\n');
    if (p == NULL)
        return 0;

    if (p - hexbuf - *offset != 128)
        return 0;

    if (oct->len + 64 > oct->max)
        return 0;

    str2hex(hexbuf + *offset, 64, oct->val + oct->len);

    *offset += 128 + 1;
    oct->len += 64;
    return 64;
}

static ECP2_FP512BN *get_p2_from_fbuf(char *buf, size_t *offset, size_t buflen)
{
    ECP2_FP512BN *pt = malloc(sizeof(ECP2_FP512BN));
    if (pt == NULL)
        goto err1;
    uint8_t val[64 * 4 + 1];
    octet oct = {0, sizeof(val), val};

    val[0] = 0x04;
    oct.len = 1;
    int i;
    for (i = 0; i < 4; i++) {
        if (64 != hex2bin_append(buf, offset, buflen, &oct))
            goto err2;
    }

    FP2_FP512BN x, y;
    BIG_512_60 x0, x1, y0, y1;
    BIG_512_60_fromBytes(x0, oct.val + 1);
    BIG_512_60_fromBytes(x1, oct.val + 1 + 64);
    BIG_512_60_fromBytes(y0, oct.val + 1 + 128);
    BIG_512_60_fromBytes(y1, oct.val + 1 + 192);
    FP2_FP512BN_from_BIGs(&x, x0, x1);
    FP2_FP512BN_from_BIGs(&y, y0, y1);
    ECP2_FP512BN_set(pt, &x, &y);
    // ECP2_FP512BN_fromOctet(pt, &oct);

    return pt;

err2:
    free(pt);
err1:
    return NULL;
}

static void free_daa_pub(daa_pub *pub)
{
    if (pub == NULL)
        return;

    if (pub->x != NULL)
        free(pub->x);
    if (pub->y != NULL)
        free(pub->y);
    free(pub);
}

static daa_pub *daa_get_issuer_pub()
{
    daa_pub *pub = malloc(sizeof(daa_pub));
    if (pub == NULL)
        goto err1;
    pub->x = NULL;
    pub->y = NULL;

    size_t buflen = 0;
    char *buf = file_to_buffer(DEFAULT_DAA_ISSUER_PUBKEY_FILE, &buflen);
    if (buf == NULL)
        goto err2;

    size_t offset = 0;
    pub->x = get_p2_from_fbuf(buf, &offset, buflen);
    if (pub->x == NULL)
        goto err3;
    pub->y = get_p2_from_fbuf(buf, &offset, buflen);
    if (pub->y == NULL)
        goto err3;

    free(buf);
    return pub;

err3:
    free(buf);
err2:
    free_daa_pub(pub);
err1:
    return NULL;
}

static void free_p1(ECP_FP512BN *p1)
{
    if (p1 == NULL)
        return;

    free(p1);
}

static int unmarshal_bn_from_bd(BIG_512_60 bn, buffer_data *bd, uint32_t *offset)
{
    if (*offset >= bd->size || *offset + 0x44 > bd->size)
        goto err1;

    uint32_t size = 0;
    memcpy((void *)&size, bd->buf + *offset, sizeof(uint32_t));
    if (size != 0x40)
        goto err1;
    *offset += sizeof(uint32_t);
    BIG_512_60_fromBytes(bn, bd->buf + *offset);
    *offset += size;

    return 1;

err1:
    return 0;
}

static ECP_FP512BN *unmarshal_p1_from_bd(buffer_data *bd, uint32_t *offset)
{
    if (*offset >= bd->size || *offset + 0x8c > bd->size)
        goto err1;

    ECP_FP512BN *p1 = malloc(sizeof(ECP_FP512BN));
    if (p1 == NULL)
        goto err1;

    uint32_t size = 0;
    memcpy((void *)&size, bd->buf + *offset, sizeof(uint32_t));
    *offset += sizeof(uint32_t);
    if (size != 0x88)
        goto err2;
    BIG_512_60 x, y;
    if (unmarshal_bn_from_bd(x, bd, offset) == 0)
        goto err2;
    if (unmarshal_bn_from_bd(y, bd, offset) == 0)
        goto err2;

    if (0 == ECP_FP512BN_set(p1, x, y))
        goto err2;

    return p1;

err2:
    free_p1(p1);
err1:
    return NULL;
}

static void free_daa_ak_cert(daa_ak_cert *cert)
{
    if (cert == NULL)
        return;

    if (cert->a != NULL)
        free(cert->a);
    if (cert->b != NULL)
        free(cert->b);
    if (cert->c != NULL)
        free(cert->c);
    if (cert->d != NULL)
        free(cert->d);
    free(cert);
}

static daa_ak_cert *unmarshal_daa_ak_cert(buffer_data *cert)
{
    daa_ak_cert *akcert = malloc(sizeof(daa_ak_cert));
    if (akcert == NULL)
        goto err1;

    akcert->a = NULL;
    akcert->b = NULL;
    akcert->c = NULL;
    akcert->d = NULL;

    uint32_t offset = 0;
    akcert->a = unmarshal_p1_from_bd(cert, &offset);
    if (akcert->a == NULL)
        goto err2;
    akcert->b = unmarshal_p1_from_bd(cert, &offset);
    if (akcert->b == NULL)
        goto err2;
    akcert->c = unmarshal_p1_from_bd(cert, &offset);
    if (akcert->c == NULL)
        goto err2;
    akcert->d = unmarshal_p1_from_bd(cert, &offset);
    if (akcert->d == NULL)
        goto err2;

    return akcert;
err2:
    free_daa_ak_cert(akcert);
err1:
    return NULL;
}

static void free_daa_signature(daa_signature *sign)
{
    if (sign == NULL)
        return;

    if (sign->j != NULL)
        free(sign->j);
    if (sign->k != NULL)
        free(sign->k);
    free(sign);
}

static daa_signature *unmarshal_daa_signature(buffer_data *sign)
{
    daa_signature *sig = malloc(sizeof(daa_signature));
    if (sig == NULL)
        goto err1;

    sig->j = NULL;
    sig->k = NULL;

    cJSON *cj = cJSON_ParseWithLength(sign->buf, sign->size);
    if (cj == NULL) {
        verifier_error("cjson parse daa signature error.");
    }
    cJSON *bsnjson = cJSON_GetObjectItemCaseSensitive(cj, "sign.bsn");
    cJSON *jjson = cJSON_GetObjectItemCaseSensitive(cj, "sign.j");
    cJSON *kjson = cJSON_GetObjectItemCaseSensitive(cj, "sign.k");
    cJSON *h2json = cJSON_GetObjectItemCaseSensitive(cj, "sign.h2");
    cJSON *sjson = cJSON_GetObjectItemCaseSensitive(cj, "sign.s");
    cJSON *nmjson = cJSON_GetObjectItemCaseSensitive(cj, "sign.nm");
    if (bsnjson == NULL || jjson == NULL || kjson == NULL || h2json == NULL || sjson == NULL || nmjson == NULL) {
        verifier_error("cjson parse daa signature error");
    }
    // base64 decode
    buffer_data j, k, h2, s, nm;
    if (strcmp(bsnjson->valuestring, "")) {
        j.buf = base64urldecode(jjson->valuestring, strlen(jjson->valuestring), &j.size);
        k.buf = base64urldecode(kjson->valuestring, strlen(kjson->valuestring), &k.size);
    }
    h2.buf = base64urldecode(h2json->valuestring, strlen(h2json->valuestring), &h2.size);
    s.buf = base64urldecode(sjson->valuestring, strlen(sjson->valuestring), &s.size);
    nm.buf = base64urldecode(nmjson->valuestring, strlen(nmjson->valuestring), &nm.size);

    // h2, s, nm
    BIG_512_60_fromBytes(sig->h2, h2.buf);
    BIG_512_60_fromBytes(sig->s, s.buf);
    BIG_512_60_fromBytes(sig->nm, nm.buf);

    // j, k
    if (strcmp(bsnjson->valuestring, "")) {
        uint32_t offset = 0;
        sig->j = unmarshal_p1_from_bd(&j, &offset);
        offset = 0;
        sig->k = unmarshal_p1_from_bd(&k, &offset);
    }

    cJSON_Delete(cj);
    return sig;
err1:
    return NULL;
}

static bool verify_daacert(daa_ak_cert *cert)
{
    bool rt = false;
    daa_pub *ispubkey = daa_get_issuer_pub();
    if (ispubkey == NULL)
        goto err1;

    ECP2_FP512BN p2;
    ECP2_FP512BN_generator(&p2);

    FP12_FP512BN lhs, rhs;

    PAIR_FP512BN_ate(&lhs, ispubkey->y, cert->a);
    PAIR_FP512BN_fexp(&lhs);

    PAIR_FP512BN_ate(&rhs, &p2, cert->b);
    PAIR_FP512BN_fexp(&rhs);

    if (!FP12_FP512BN_equals(&lhs, &rhs))
        goto err2;

    ECP_FP512BN ptemp;

    ECP_FP512BN_copy(&ptemp, cert->d);
    ECP_FP512BN_add(&ptemp, cert->a);
    PAIR_FP512BN_ate(&lhs, ispubkey->x, &ptemp);
    PAIR_FP512BN_fexp(&lhs);

    PAIR_FP512BN_ate(&rhs, &p2, cert->c);
    PAIR_FP512BN_fexp(&rhs);

    if (!FP12_FP512BN_equals(&lhs, &rhs))
        goto err2;

    rt = true;

err2:
    free_daa_pub(ispubkey);
err1:
    return rt;
}

static void hash_update_buf(SHA512_CTX *ctx, char *buf, int size)
{
    SHA512_Update(ctx, (char *)&size, sizeof(int));
    if (size > 0)
        SHA512_Update(ctx, buf, size);
}

static void hash_update_p1(SHA512_CTX *ctx, ECP_FP512BN *p1)
{
    BIG_512_60 x, y;
    char v_tmp[SHA512_DIGEST_LENGTH];
    int p1_size = 2 * (sizeof(v_tmp) + sizeof(int));

    ECP_FP512BN_get(x, y, p1);

    SHA512_Update(ctx, (char *)&p1_size, sizeof(int));
    BIG_512_60_toBytes(v_tmp, x);
    hash_update_buf(ctx, v_tmp, sizeof(v_tmp));
    BIG_512_60_toBytes(v_tmp, y);
    hash_update_buf(ctx, v_tmp, sizeof(v_tmp));
}

static bool verify_daasig(buffer_data *mhash, daa_signature *sig, daa_ak_cert *cert)
{
    ECP_FP512BN l, e, s_j, h2_k, s_b, h2_d;

    // may need additional step to verify J while bsn is available
    // s1,y1=Hs(bsn); verify J=(Hp(s1),y1)

    // skip J, K, L caculation while J is null.
    if (sig->j != NULL) {
        ECP_FP512BN_copy(&s_j, sig->j);
        ECP_FP512BN_mul(&s_j, sig->s);
        ECP_FP512BN_copy(&h2_k, sig->k);
        ECP_FP512BN_mul(&h2_k, sig->h2);
        ECP_FP512BN_copy(&l, &s_j);
        ECP_FP512BN_sub(&l, &h2_k);
    }

    ECP_FP512BN_copy(&s_b, cert->b);
    ECP_FP512BN_mul(&s_b, sig->s);
    ECP_FP512BN_copy(&h2_d, cert->d);
    ECP_FP512BN_mul(&h2_d, sig->h2);
    ECP_FP512BN_copy(&e, &s_b);
    ECP_FP512BN_sub(&e, &h2_d);

    // calculate c=H(H(m),A,B,C,D,J,K,L,E))
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    // H(m)
    hash_update_buf(&ctx, mhash->buf, mhash->size);
    // A
    hash_update_p1(&ctx, cert->a);
    // B
    hash_update_p1(&ctx, cert->b);
    // C
    hash_update_p1(&ctx, cert->c);
    // D
    hash_update_p1(&ctx, cert->d);
    if (sig->j != NULL) {
        // J
        hash_update_p1(&ctx, sig->j);
        // K
        hash_update_p1(&ctx, sig->k);
        // L
        hash_update_p1(&ctx, &l);
    } else {
        hash_update_buf(&ctx, NULL, 0);
        hash_update_buf(&ctx, NULL, 0);
        hash_update_buf(&ctx, NULL, 0);
    }
    // E
    hash_update_p1(&ctx, &e);

    uint8_t c[SHA512_DIGEST_LENGTH];
    SHA512_Final(c, &ctx);

    octet tmp = {SHA512_DIGEST_LENGTH, SHA512_DIGEST_LENGTH, mhash->buf};

    // caclulate h1=H(c); h2=Hn(nm || h1)
    uint8_t h1[SHA512_DIGEST_LENGTH];
    _SHA512(c, sizeof(c), h1);

    SHA512_Init(&ctx);

    uint8_t nm[SHA512_DIGEST_LENGTH];
    BIG_512_60_toBytes(nm, sig->nm);
    hash_update_buf(&ctx, nm, sizeof(nm));
    hash_update_buf(&ctx, h1, sizeof(h1));

    uint8_t h2[SHA512_DIGEST_LENGTH];
    SHA512_Final(h2, &ctx);

    BIG_512_60 b_h2, n;
    BIG_512_60_fromBytes(b_h2, h2);
    BIG_512_60_rcopy(n, CURVE_Order_FP512BN);
    BIG_512_60_mod(b_h2, n);

    if (BIG_512_60_comp(b_h2, sig->h2) != 0)
        return false;

    return true;
}

static bool verifysig_daacert(buffer_data *data, buffer_data *sign, buffer_data *cert)
{
    bool rt = false;

    // parse daa ak cert
    daa_ak_cert *akcert = unmarshal_daa_ak_cert(cert);
    if (akcert == NULL)
        goto err1;

    // parse daa signature
    daa_signature *sig = unmarshal_daa_signature(sign);
    if (sig == NULL)
        goto err2;

    // verify daa ak cert
    rt = verify_daacert(akcert);
    if (!rt)
        goto err3;

    // caculate the digest of the data
    uint8_t digest[SHA512_DIGEST_LENGTH];
    _SHA512(data->buf, data->size, digest);

    // perform signature verification
    buffer_data mhash = {sizeof(digest), digest};
    rt = verify_daasig(&mhash, sig, akcert);

err3:
    free_daa_signature(sig);
err2:
    free_daa_ak_cert(akcert);
err1:
    return rt;
}

/*
verifysig will verify the signature in report
   data: data protected by signature, a byte array
   sign: the signature, a byte array
   cert: a byte array.
      A drk signed cert in self-defined format for scenario 0;
      A X509 PEM cert for scenario 1.
      A DAA cert scenario 2.
   scenario: 0, 1 or 2. refer to the description above.
   return value: true if the sigature verification succeeded, else false.
*/
bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *cert, uint32_t scenario)
{
    if (data->size <= 0 || sign->size <= 0 || cert->size <= 0 || scenario > 2) {
        return false;
    }

    switch (scenario) {
    case 0:
        return verifysig_drksignedcert(data, sign, cert);
    case 1:
        return verifysig_x509cert(data, sign, cert, TAS_ROOT_CERT_PATH);
    case 2:
        return verifysig_daacert(data, sign, cert);
    }

    return false;
}

void dumpDrkCert(buffer_data *certdrk)
{
    FILE *f = fopen("drk.crt", "wb");
    if (!f) {
        fprintf(stderr, "unable to open: %s\n", "test.cert");
        return;
    }
    fwrite(certdrk->buf, sizeof(char), certdrk->size, f);
    fclose(f);
}

bool restorePEMCert(uint8_t *data, int data_len, buffer_data *certdrk)
{
    uint8_t head[] = "-----BEGIN CERTIFICATE-----\n";
    uint8_t end[] = "-----END CERTIFICATE-----\n";

    // trim ending '\0' from data
    trim_ending_0(data, &data_len);

    // calculate out len and check out buffer size
    int out_len = data_len + (data_len + 63) / 64 + strlen(head) + strlen(end);
    if (out_len > certdrk->size) {
        printf("failed to restore drk cert: drk cert is too large.\n");
        return false;
    }

    // copy head
    uint8_t *dst = certdrk->buf;
    out_len = strlen(head);
    memcpy(dst, head, out_len);
    dst += out_len;

    // copy data
    uint8_t *src = data;
    int loop = data_len / 64;
    int rem = data_len % 64;
    int i;

    for (i = 0; i < loop; i++, src += 64, dst += 65) {
        memcpy(dst, src, 64);
        dst[64] = '\n';
    }
    if (rem > 0) {
        memcpy(dst, src, rem);
        dst[rem] = '\n';
        dst += rem + 1;
    }

    // copy end
    out_len = strlen(end);
    memcpy(dst, end, out_len);
    certdrk->size = dst + out_len - certdrk->buf;

    return true;
}

void free_ta_attr(TA_attr *attr)
{
    if (attr == NULL)
        return;
    if (attr->type == 0) {
        if (attr->data.reserve == NULL)
            return;
        if (attr->data.reserve->buf)
            free(attr->data.reserve->buf);
        free(attr->data.reserve);
        return;
    }
    if (attr->type == 1) {
        if (attr->data.container == NULL)
            return;
        if (attr->data.container->id.buf)
            free(attr->data.container->id.buf);
        if (attr->data.container->type.buf)
            free(attr->data.container->type.buf);
        free(attr->data.container);
        return;
    }
}

void free_report(TA_report *report)
{
    if (NULL == report)
        return;

    if (NULL != report->signature) {
        if (NULL != report->signature->buf)
            free(report->signature->buf);
        free(report->signature);
    }

    if (NULL != report->cert) {
        if (NULL != report->cert->buf)
            free(report->cert->buf);
        free(report->cert);
    }

    free_ta_attr(&(report->ta_attr));

    free(report);
}

// getDataFromReport get some data which have akcert & signak & signdata &
// scenario from report
bool getDataFromReport(buffer_data *data, buffer_data *akcert, buffer_data *signak, buffer_data *signdata,
                       uint32_t *scenario)
{
    if (data->buf == NULL) {
        printf("report is null");
        return false;
    }
    TA_report *report;
    report = Convert(data);
    if (report == NULL) {
        printf("failed to parse the report\n");
        return false;
    }
    *scenario = report->scenario;
    akcert->size = report->cert->size;
    akcert->buf = malloc(akcert->size);
    memcpy(akcert->buf, report->cert->buf, report->cert->size);
    signak->size = report->signature->size;
    signak->buf = malloc(signak->size);
    memcpy(signak->buf, report->signature->buf, report->signature->size);

    // get payload
    cJSON *cj = cJSON_ParseWithLength(data->buf, data->size);
    if (cj == NULL) {
        verifier_error("cjson parse report error.");
    }

    cJSON *pljson = cJSON_GetObjectItemCaseSensitive(cj, "payload");
    uint8_t *tmp = cJSON_Print(pljson);
    signdata->size = strlen(tmp) / 3 * 4 + 4 + 1;
    signdata->buf = malloc(signdata->size);
    base64urlencode(tmp, strlen(tmp), signdata->buf, &signdata->size);

    cJSON_Delete(cj);
    free_report(report);
    cJSON_free(tmp);
    return true;
}

// get some data which have signdata signdrk certdrk and akpub from akcert
bool getDataFromAkCert(buffer_data *akcert, buffer_data *signdata, buffer_data *signdrk, buffer_data *certdrk,
                       buffer_data *akpub)
{
    bool rt = false;
    if (akcert->buf == NULL) {
        printf("akcert is null");
        return rt;
    }

    // parse akcert
    cJSON *cj = cJSON_ParseWithLength((char *)akcert->buf, akcert->size);
    if (cj == NULL) {
        printf("cjson parse akcert error!\n");
        return rt;
    }
    // get payload and signature
    cJSON *pljson = cJSON_GetObjectItemCaseSensitive(cj, "payload");
    cJSON *sigjson = cJSON_GetObjectItemCaseSensitive(cj, "signature");
    if (pljson == NULL || sigjson == NULL) {
        printf("cjson parse akcert error, failed to get payload and signature!\n");
        goto err;
        // return false;
    }
    // get akpub, signdrk, certdrk, signdata
    cJSON *akpubjson = cJSON_GetObjectItemCaseSensitive(pljson, "ak_pub");
    cJSON *signdrkjson = cJSON_GetObjectItemCaseSensitive(sigjson, "drk_sign");
    cJSON *certdrkjson = cJSON_GetObjectItemCaseSensitive(sigjson, "drk_cert");
    if (akpubjson == NULL || signdrkjson == NULL || certdrkjson == NULL) {
        printf("cjson parse akcert error, failed to get akpub, signdrk and certdrk!\n");
        goto err;
        // return false;
    }
    /*
       akpub->buf: AK_PUB_TYPE. outdata is the same as previous
       signdrk->buf*: BASE64_TYPE, DRK signature for "payload". outdata has been decoded already
       certdrk->buf: BASE64_TYPE, BASE 64 of DRK cert. outdata is the same as previous
       signdata->buf*: payload, outdata can be directly used to hash
    */

    // ak_pub: build a pub key with the modulus carried in drk issued cert
    rt = decodeAKPubKey(akpubjson, akpub);
    if (!rt) {
        printf("base64 decode ak public key failed!\n");
        goto err;
        // return NULL;
    }

    // drk_sign: base64 decoded
    uint8_t *tmp1 = (uint8_t *)signdrkjson->valuestring;
    signdrk->buf = base64urldecode(tmp1, strlen(tmp1), &signdrk->size);

    // signdata: base64 encoded (can be directly used to hash)
    uint8_t *signdatatmp = (uint8_t *)cJSON_Print(pljson);
    signdata->size = 4096;
    signdata->buf = (uint8_t *)malloc(sizeof(uint8_t) * signdata->size);
    base64urlencode(signdatatmp, strlen(signdatatmp), signdata->buf, &signdata->size);

    // drk_cert: base64 decoded & restore
    buffer_data certdrktmp1;
    uint8_t *tmp2 = (uint8_t *)certdrkjson->valuestring;
    certdrktmp1.buf = base64urldecode(tmp2, strlen(tmp2), &certdrktmp1.size);
    certdrk->size = 4300;
    certdrk->buf = (uint8_t *)malloc(sizeof(uint8_t) * certdrk->size);
    rt = restorePEMCert(certdrktmp1.buf, certdrktmp1.size, certdrk);

    free(certdrktmp1.buf);
    cJSON_free(signdatatmp);
err:
    cJSON_Delete(cj);
    return rt;
}

bool tee_verify_signature(buffer_data *report)
{
    // get akcert signak signdata from report
    buffer_data akcert, signak, signdata;
    uint32_t scenario;
    bool rt = getDataFromReport(report, &akcert, &signak, &signdata, &scenario);
    if (!rt) {
        printf("get Data From Report is failed\n");
        return false;
    }
    rt = verifysig(&signdata, &signak, &akcert, scenario);
    if (!rt) {
        printf("verify signature is failed\n");
        return false;
    }
    printf("Verify signature success!\n");
    return true;
}

/*
void verifier_error(const char *msg)
{
   printf("%s\n", msg);
   exit(EXIT_FAILURE);
}

void file_error(const char *s)
{
   printf("Couldn't open file: %s\n", s);
   exit(EXIT_FAILURE);
}
*/
void test_print(uint8_t *printed, int printed_size, char *printed_name)
{
    printf("%s:\n", printed_name);
    for (int i = 0; i < printed_size; i++) {
        printf("%02X", printed[i]);
        if (i % 32 == 31) {
            printf("\n");
        }
    }
    printf("\n");
};

static bool compare_buffer_data(buffer_data *a, buffer_data *b)
{
    if (a == NULL || b == NULL || a->buf == NULL || b->buf == NULL) {
        printf("buffer_data input is invalid\n");
        return false;
    }

    if (a->size != b->size) {
        return false;
    }

    return cmp_bytes(a->buf, b->buf, a->size);
}

static bool compare_container_info(container_info *info, TA_report *report)
{
    if (report == NULL) {
        printf("report input is invalid\n");
        return false;
    }

    /* no need to compare container info when report not contain container info */
    if (report->ta_attr.type != 1) {
        return true;
    }

    if (info == NULL || report->ta_attr.data.container == NULL) {
        printf("report ta_attr or container info is invalid\n");
        return false;
    }

    return compare_buffer_data(&(info->id), &(report->ta_attr.data.container->id)) &&
           compare_buffer_data(&(info->type), &(report->ta_attr.data.container->type));
}


bool tee_verify(buffer_data *bufdata, container_info *info, int type, char *filename)
{
    TA_report *report = Convert(bufdata);
    base_value *qta_report_baseval = NULL;
    base_value *baseval = LoadBaseValue(report, filename, &qta_report_baseval);

    bool verified = false;
    if ((report == NULL) || (baseval == NULL)) {
        printf("convert report or basevalue file failed!\n");
        goto end;
    }

    if (!compare_container_info(info, report)) {
        printf("compare container id or type failed\n");
        goto end;
    }

    verified = Compare(type, report, baseval, qta_report_baseval); // compare the report with the basevalue

end:
    if (report)
        free_report(report);
    if (baseval)
        free(baseval);
    if (qta_report_baseval)
        free(qta_report_baseval);
    return verified;
}

bool get_nonce_from_payload(cJSON *pljson, TA_report *tr)
{
    // get nonce: base64 -> uint8_t*
    cJSON *njson = cJSON_GetObjectItemCaseSensitive(pljson, "nonce");
    if (njson == NULL) {
        printf("cjson parse nonce from report error");
        return false;
    }
    int len = 0;
    uint8_t *tmp = base64urldecode(njson->valuestring, strlen(njson->valuestring), &len);
    memset(tr->nonce, 0, 64);
    memcpy(tr->nonce, tmp, len);
    return true;
}

bool get_uuid_from_payload(cJSON *pljson, TA_report *tr)
{
    // get uuid: string -> uint8_t*
    cJSON *ujson = cJSON_GetObjectItemCaseSensitive(pljson, "uuid");
    if (ujson == NULL) {
        printf("cjson parse uuid from report error");
        return false;
    }
    str_to_uuid(ujson->valuestring, tr->uuid);

    return true;
}

bool get_hash_from_payload(cJSON *pljson, TA_report *tr)
{
    // get img&mem hash: base64 -> uint8_t*
    cJSON *imgjson = cJSON_GetObjectItemCaseSensitive(pljson, "ta_img");
    cJSON *memjson = cJSON_GetObjectItemCaseSensitive(pljson, "ta_mem");
    if (imgjson == NULL || memjson == NULL) {
        printf("cjson parse hash from report error");
        return false;
    }

    int len = 0;
    uint8_t *tmp1 = base64urldecode(imgjson->valuestring, strlen(imgjson->valuestring), &len);
    memcpy(tr->image_hash, tmp1, 32);

    uint8_t *tmp2 = base64urldecode(memjson->valuestring, strlen(memjson->valuestring), &len);
    memcpy(tr->hash, tmp2, 32);

    free(tmp1);
    free(tmp2);
    return true;
}

bool get_scenario_from_report(cJSON *pljson, cJSON *signjson, cJSON *acjson, TA_report *tr)
{
    if (pljson == NULL || signjson == NULL || acjson == NULL || tr == NULL) {
        printf("invalid input parameter\n");
        return false;
    }
    cJSON *scejson = cJSON_GetObjectItemCaseSensitive(pljson, "scenario");
    if (scejson == NULL) {
        printf("cjson parse scenario from report error\n");
        return false;
    }
    tr->signature = malloc(sizeof(buffer_data));
    tr->cert = malloc(sizeof(buffer_data));
    if (strcmp(scejson->valuestring, RA_SCENARIO_NO_AS) == 0) {
        tr->scenario = RA_SCENARIO_NO_AS_INT;
        // signature: no as
        cJSON *noasjson = cJSON_GetObjectItemCaseSensitive(signjson, "sce_no_as");
        tr->signature->buf =
            base64urldecode(noasjson->valuestring, strlen(noasjson->valuestring), &tr->signature->size);
        // akcert: no as (parse needed)
        cJSON *c1json = cJSON_GetObjectItemCaseSensitive(acjson, "sce_no_as");
        tr->cert->buf = cJSON_Print(c1json);
        tr->cert->size = strlen(tr->cert->buf);

    } else if (strcmp(scejson->valuestring, RA_SCENARIO_AS_NO_DAA) == 0) {
        tr->scenario = RA_SCENARIO_AS_NO_DAA_INT;
        // signature: as no daa
        cJSON *asjson = cJSON_GetObjectItemCaseSensitive(signjson, "sce_as_no_daa");
        tr->signature->buf = base64urldecode(asjson->valuestring, strlen(asjson->valuestring), &tr->signature->size);
        // akcert: as no daa
        cJSON *c2json = cJSON_GetObjectItemCaseSensitive(acjson, "sce_as_no_daa");
        tr->cert->buf = base64urldecode(c2json->valuestring, strlen(c2json->valuestring), &tr->cert->size);

    } else if (strcmp(scejson->valuestring, RA_SCENARIO_AS_WITH_DAA) == 0) {
        tr->scenario = RA_SCENARIO_AS_WITH_DAA_INT;
        // signature: daa (parse needed)
        cJSON *daajson = cJSON_GetObjectItemCaseSensitive(signjson, "sce_as_with_daa");
        tr->signature->buf = cJSON_Print(daajson);
        tr->signature->size = strlen(tr->signature->buf);
        // akcert: daa
        cJSON *c3json = cJSON_GetObjectItemCaseSensitive(acjson, "sce_as_with_daa");
        tr->cert->buf = base64urldecode(c3json->valuestring, strlen(c3json->valuestring), &tr->cert->size);

    } else {
        printf("invalid scenario");
        return false;
    }
    return true;
}

bool get_alg_from_payload(cJSON *pljson, TA_report *tr)
{
    // get hash&sign algorithm: string -> uint32_t
    cJSON *sjson = cJSON_GetObjectItemCaseSensitive(pljson, "sign_alg");
    cJSON *hjson = cJSON_GetObjectItemCaseSensitive(pljson, "hash_alg");
    if (hjson == NULL || sjson == NULL) {
        printf("cjson parse algorithm from report error");
        return false;
    }

    if (strcmp(sjson->valuestring, RA_SIGN_ALG_RSA4096) == 0) {
        tr->sig_alg = RA_ALG_RSA_4096;
    }
    if (strcmp(hjson->valuestring, RA_HASH_ALG_SHA256) == 0) {
        tr->hash_alg = RA_ALG_SHA_256;
    }
    return true;
}

static bool base64urldecode_copy(char *src, uint8_t *dst, int dstMax_len)
{
    if (src == NULL || dst == NULL || dstMax_len <= 0) {
        printf("input params error\n");
        return false;
    }

    int len = 0;
    uint8_t *tmp = base64urldecode(src, strlen(src), &len);
    if (len > dstMax_len) {
        printf("base64urldecode len is overflow\n");
        free(tmp);
        return false;
    }
    memcpy(dst, tmp, len);
    free(tmp);
    return true;
}

static bool create_copy_buf(char *src, buffer_data *dst)
{
    if (src == NULL || dst == NULL) {
        printf("input params error\n");
        return false;
    }

    dst->size = 0;
    dst->buf = NULL;

    dst->size = strlen(src);
    if (dst->size == 0) {
        return true;
    }

    dst->buf = (uint8_t *)malloc(dst->size);
    if (dst->buf== NULL) {
        printf("malloc buf failed\n");
        return false;
    }

    memcpy(dst->buf, src, dst->size);
    return true;
}

static bool get_complex_ta_attr(cJSON *attr_json, TA_report *tr)
{
    if (attr_json == NULL || tr == NULL || attr_json->child == NULL) {
        printf("input params error\n");
        return false;
    }

    tr->ta_attr.type = 1;
    cJSON *id = cJSON_GetObjectItemCaseSensitive(attr_json, "container_id");
    cJSON *type = cJSON_GetObjectItemCaseSensitive(attr_json, "container_type");
    cJSON *imgjson = cJSON_GetObjectItemCaseSensitive(attr_json, "qta_report_img_hash");
    cJSON *memjson = cJSON_GetObjectItemCaseSensitive(attr_json, "qta_report_mem_hash");
    if (id == NULL || type == NULL || imgjson == NULL || memjson == NULL) {
        printf("cjson parse attr data from report error\n");
        return false;
    }

    Container_attr *ta_attr = (Container_attr *)calloc(1, sizeof(Container_attr));
    if (ta_attr == NULL) {
        printf("malloc ta_attr node failed\n");
        return false;
    }

    if (!base64urldecode_copy(imgjson->valuestring, ta_attr->img_hash, HASH_SIZE) ||
        !base64urldecode_copy(memjson->valuestring, ta_attr->mem_hash, HASH_SIZE)) {
        printf("decode qta_report hash failed\n");
        free(ta_attr);
        return false;
    }

    if (!create_copy_buf(id->valuestring, &ta_attr->id) || !create_copy_buf(type->valuestring, &ta_attr->type)) {
        printf("read and copy container info failed\n");
        free(ta_attr);
        return false;
    }

    tr->ta_attr.data.container = ta_attr;
    return true;
}

static bool get_ta_attr(cJSON *attr_json, TA_report *tr)
{
    if (attr_json == NULL || tr == NULL) {
        printf("input params error\n");
        return false;
    }

    if (attr_json->child == NULL) {
        tr->ta_attr.type = 0;
        buffer_data *buf_node = (buffer_data *)calloc(1, sizeof(buffer_data));
        if (buf_node == NULL) {
            printf("malloc reserve node failed\n");
            return false;
        }

        /* ta_attr data storaged in buf */
        if (!create_copy_buf(attr_json->valuestring, buf_node)) {
            printf("read and copy reserve buf failed\n");
            free(buf_node);
            return false;
        }
        tr->ta_attr.data.reserve = buf_node;
        return true;
    }

    return get_complex_ta_attr(attr_json, tr);
}

bool get_other_params_from_report(cJSON *pljson, TA_report *tr)
{
    // get version, timestamp, ta_attr
    cJSON *vjson = cJSON_GetObjectItemCaseSensitive(pljson, "version");
    cJSON *tsjson = cJSON_GetObjectItemCaseSensitive(pljson, "timestamp");
    cJSON *reservejson = cJSON_GetObjectItemCaseSensitive(pljson, "ta_attr");
    if (vjson == NULL || tsjson == NULL || reservejson == NULL) {
        printf("cjson parse algorithm from report error");
        return false;
    }

    memcpy(tr->timestamp, tsjson->valuestring, strlen(tsjson->valuestring));
    memcpy(tr->version, vjson->valuestring, strlen(vjson->valuestring));

    if (!get_ta_attr(reservejson, tr)) {
        printf("cjson parse ta_attr error\n");
        return false;
    }

    return true;
}

TA_report *Convert(buffer_data *data)
{
    TA_report *report = NULL;

    // determine whether the buffer is legal
    if (data == NULL)
        verifier_error("illegal buffer data pointer.");
    if (data->size > DATABUFMAX || data->size < DATABUFMIN)
        verifier_error("size of buffer is illegal.");

    // parse report
    // printf(data->buf);
    cJSON *cj = cJSON_ParseWithLength(data->buf, data->size);
    if (cj == NULL) {
        verifier_error("cjson parse report error.");
    }
    // get payload, report_sign, akcert
    cJSON *pljson = cJSON_GetObjectItemCaseSensitive(cj, "payload");
    cJSON *sigjson = cJSON_GetObjectItemCaseSensitive(cj, "report_sign");
    cJSON *acjson = cJSON_GetObjectItemCaseSensitive(cj, "akcert");
    if (pljson == NULL || sigjson == NULL || acjson == NULL) {
        printf("cjson parse report error");
        goto err1;
    }
    report = (TA_report *)calloc(1, sizeof(TA_report));
    if (report == NULL) {
        printf("out of memory.");
        goto err1;
    }

    bool rt = get_nonce_from_payload(pljson, report);
    if (!rt) {
        printf("get nonce from report error");
        goto err2;
    }
    rt = get_uuid_from_payload(pljson, report);
    if (!rt) {
        printf("get uuid from report error");
        goto err2;
    }
    rt = get_hash_from_payload(pljson, report);
    if (!rt) {
        printf("get hash from report error");
        goto err2;
    }
    rt = get_alg_from_payload(pljson, report);
    if (!rt) {
        printf("get hash & sign algorithm from report error");
        goto err2;
    }
    rt = get_other_params_from_report(pljson, report);
    if (!rt) {
        printf("get version & timestamp & ta_attr from report error");
        goto err2;
    }
    // get scenario & sign & cert from report
    rt = get_scenario_from_report(pljson, sigjson, acjson, report);
    if (!rt) {
        printf("get scenario & sign & cert from report error");
        goto err2;
    }
    // signature & cert are different from the previous data
    cJSON_Delete(cj);
    return report;

err2:
    free_report(report);
err1:
    cJSON_Delete(cj);
    return NULL;
}

// void parse_uuid(uint8_t *uuid, TEE_UUID bufuuid) {
//     size_t offset = 0;

//     read_bytes(&(bufuuid.timeLow), sizeof(uint32_t), 1, uuid, &offset);
//     read_bytes(&(bufuuid.timeMid), sizeof(uint16_t), 1, uuid, &offset);
//     read_bytes(&(bufuuid.timeHiAndVersion), sizeof(uint16_t), 1, uuid,
//     &offset); read_bytes(&(bufuuid.clockSeqAndNode), sizeof(uint8_t),
//     NODE_LEN, uuid, &offset);
// }

void read_bytes(void *input, size_t size, size_t nmemb, uint8_t *output, size_t *offset)
{
    memcpy(output + *offset, input, size * nmemb);
    *offset += size * nmemb;
}

static uint8_t g_qta_report_uuid[UUID_SIZE] = {0xe0, 0xc0, 0x84, 0x4f, 0x3f, 0x4c, 0x2f, 0x42,
                                               0x97, 0xdc, 0x14, 0xbf, 0xa2, 0x31, 0x4a, 0xd1};

static base_value *create_basevalue(const uint8_t *uuid, char *img_str, char *mem_str)
{
    if (uuid == NULL || img_str == NULL || mem_str == NULL) {
        printf("invalid input\n");
        return NULL;
    }

    base_value *baseval = (base_value *)calloc(1, sizeof(base_value));
    if (baseval == NULL) {
        printf("calloc basevalue failed\n");
        return NULL;
    }

    memcpy(baseval->uuid, uuid, UUID_SIZE);
    str_to_hash(img_str, baseval->valueinfo[0]);
    str_to_hash(mem_str, baseval->valueinfo[1]);
    return baseval;
}

static bool found_baseval(char *fbuf, const uint8_t *ta_uuid, base_value **ta, base_value **qta_report, bool need_qta_report)
{
    if (fbuf == NULL || ta_uuid == NULL || ta == NULL || qta_report == NULL) {
        printf("invalid input\n");
        return false;
    }

    *ta = NULL;
    *qta_report = NULL;
    // fbuf is string stream.
    char *line = NULL;
    line = strtok(fbuf, "\n");

    char uuid_str[37], image_hash_str[65], hash_str[65];
    uint8_t cur_uuid[UUID_SIZE] = {0};
    bool found_ta = false, found_qta_report = !need_qta_report;

    while (line != NULL) {
        sscanf(line, "%36s %64s %64s", uuid_str, image_hash_str, hash_str);
        str_to_uuid(uuid_str, cur_uuid);
        if (cmp_bytes(ta_uuid, cur_uuid, UUID_SIZE)) {
            *ta = create_basevalue(ta_uuid, image_hash_str, hash_str);
            if (*ta == NULL) {
                printf("found ta basevalue, but malloc basevalue failed\n");
                goto err;
            }
            found_ta = true;
            if (found_qta_report)
                break;
        }
        if (need_qta_report) {
            if (cmp_bytes(g_qta_report_uuid, cur_uuid, UUID_SIZE)) {
                *qta_report = create_basevalue(g_qta_report_uuid, image_hash_str, hash_str);
                if (*qta_report == NULL) {
                    printf("found qta_report basevalue, but malloc basevalue failed\n");
                    goto err;
                }
                found_qta_report = true;
                if (found_ta)
                    break;
            }
        }

        line = strtok(NULL, "\n");
    }

    if (!found_ta || !found_qta_report) {
        printf("not found the ta basevalue\n");
        goto err;
    }
    return true;

err:
    if (*ta) {
        free(*ta);
        *ta = NULL;
    }
    if (*qta_report) {
        free(*qta_report);
        *qta_report = NULL;
    }
    return false;
}

base_value *LoadBaseValue(const TA_report *report, char *filename, base_value **qta_report_baseval)
{
    if (report == NULL || filename == NULL || qta_report_baseval == NULL) {
        printf("input argument is invalid\n");
        return NULL;
    }

    base_value *baseval = NULL;
    size_t fbuf_len = 0; // if needed

    char *fbuf = file_to_buffer(filename, &fbuf_len);
    if (fbuf == NULL) {
        printf("read basevalue file %d failed\n", filename);
        return NULL;
    }

    bool is_container = (report->ta_attr.type == 1);
    if (!found_baseval(fbuf, report->uuid, &baseval, qta_report_baseval, is_container)) {
        printf("found basevalue failed\n");
    }
    
end:
    free(fbuf);
    return baseval;
}

void reverse(uint8_t *bytes, int size)
{
    for (int i = 0; i < size / 2; i++) {
        int tmp = bytes[i];
        bytes[i] = bytes[size - 1 - i];
        bytes[size - 1 - i] = tmp;
    }
}

void str_to_uuid(const char *str, uint8_t *uuid)
{
    char substr1[9];
    char substr2[5];
    char substr3[5];
    char substr4[5];
    char substr5[13];
    // 8-4-4-4-12
    sscanf(str, "%8[^-]-%4[^-]-%4[^-]-%4[^-]-%12[^-]", substr1, substr2, substr3, substr4, substr5);
    str2hex(substr1, 4, uuid);
    reverse(uuid, 4);
    str2hex(substr2, 2, uuid + 4);
    reverse(uuid + 4, 2);
    str2hex(substr3, 2, uuid + 4 + 2);
    reverse(uuid + 4 + 2, 2);
    str2hex(substr4, 2, uuid + 4 + 2 + 2);
    str2hex(substr5, 6, uuid + 4 + 2 + 2 + 2);
}

void uuid_to_str(const uint8_t *uuid, char *str)
{
    uint8_t tmp[4];
    // 8-
    memcpy(tmp, uuid, 4);
    reverse(tmp, 4);
    hex2str(tmp, 4, str);
    strcpy(str + 4 * 2, "-");
    //  str[4*2] = "-";
    // 8-4-
    memcpy(tmp, uuid + 4, 2);
    reverse(tmp, 2);
    hex2str(tmp, 2, str + 9);
    strcpy(str + 9 + 2 * 2, "-");
    //  str[9+2*2] = "-";
    // 8-4-4-
    memcpy(tmp, uuid + 4 + 2, 2);
    reverse(tmp, 2);
    hex2str(tmp, 2, str + 14);
    strcpy(str + 14 + 2 * 2, "-");
    //  str[14+2*2] = "-";
    // 8-4-4-4-
    hex2str(uuid + 4 + 2 + 2, 2, str + 19);
    strcpy(str + 19 + 2 * 2, "-");
    //  str[19+2*2] = "-";
    // 8-4-4-4-12
    hex2str(uuid + 4 + 2 + 2 + 2, 6, str + 24);
}

void str_to_hash(const char *str, uint8_t *hash)
{
    // 64 bit -> 32 bit
    str2hex(str, HASH_SIZE, hash);
}

void hash_to_str(const uint8_t *hash, char *str)
{
    // 32 bit -> 64 bit
    hex2str(hash, HASH_SIZE, str);
}

void hex2str(const uint8_t *source, int source_len, char *dest)
{
    int i;
    unsigned char HighByte;
    unsigned char LowByte;

    for (i = 0; i < source_len; i++) {
        HighByte = source[i] >> 4;  // get high 4bit from a byte
        LowByte = source[i] & 0x0f; // get low 4bit

        HighByte += 0x30;     // Get the corresponding char, and skip 7 symbols if
                              // it's a letter
        if (HighByte <= 0x39) // number
            dest[i * 2] = HighByte;
        else                               // letter
            dest[i * 2] = HighByte + 0x07; // Get the char and save it to the corresponding position

        LowByte += 0x30;
        if (LowByte <= 0x39)
            dest[i * 2 + 1] = LowByte;
        else
            dest[i * 2 + 1] = LowByte + 0x07;
    }
}

void str2hex(const char *source, int source_len, uint8_t *dest)
{
    int i;
    unsigned char HighByte;
    unsigned char LowByte;

    for (i = 0; i < source_len; i++) {
        HighByte = toupper(source[i * 2]); // If lower case is encountered,
                                           // uppercase processing is performed
        LowByte = toupper(source[i * 2 + 1]);

        if (HighByte <= 0x39) // 0x39 corresponds to the character '9', where it
                              // is a number
            HighByte -= 0x30;

        else // Otherwise, it is a letter, and 7 symbols need to be skipped
            HighByte -= 0x37;

        if (LowByte <= 0x39)
            LowByte -= 0x30;

        else
            LowByte -= 0x37;

        /*
         *  Let's say the string "3c"
         *     HighByte = 0x03, binary is 0000 0011
         *     LowByte = 0x0c, binary is 0000 1100
         *
         *      HighByte << 4 = 0011 0000
         *      HighByte | LowByte :
         *
         *      0011 0000
         *      0000 1100
         *    -------------
         *      0011 1100
         *
         *      that is 0x3c
         *
         **/
        dest[i] = (HighByte << 4) | LowByte;
    }
}

char *file_to_buffer(char *file, size_t *file_length)
{
    FILE *f = NULL;
    char *buffer = NULL;

    f = fopen(file, "rb");
    if (!f) {
        printf("Couldn't open file: %s\n", file);
        return NULL;
    }
    fseek(f, 0L, SEEK_END);
    *file_length = ftell(f);
    rewind(f);
    buffer = (char *)malloc(*file_length + 1);
    if (NULL == buffer) {
        goto err;
    }
    size_t result = fread(buffer, 1, *file_length, f);
    if (result != *file_length) {
        free(buffer);
        buffer = NULL;
    }

err:
    fclose(f);
    return buffer;
}

bool Compare(int type, TA_report *report, base_value *basevalue, base_value *qta_baseval)
{
    if (report == NULL || basevalue == NULL) {
        printf("invalid input\n");
        return false;
    }
    bool is_container = (report->ta_attr.type == 1);
    if (is_container && (qta_baseval == NULL || report->ta_attr.data.container == NULL)) {
        printf("need qta_report basevalue and hash\n");
        return false;
    }
    Container_attr *attr = report->ta_attr.data.container;

    bool compared = false, qta_compared = !is_container;
    /*
       test_print(report->image_hash, HASH_SIZE, "report->image_hash");
       test_print(report->hash, HASH_SIZE, "report->hash");
       test_print(basevalue->valueinfo[0], HASH_SIZE, "basevalue->valueinfo[0]");
       test_print(basevalue->valueinfo[1], HASH_SIZE, "basevalue->valueinfo[1]");
       test_print(report->uuid, 16, "report->uuid");
       test_print(basevalue->uuid, 16, "basevalue->uuid");
    */
    switch (type) {
    case 1:
        printf("%s\n", "Compare image measurement..");
        compared = cmp_bytes(report->image_hash, basevalue->valueinfo[0], HASH_SIZE);
        if (is_container) {
            qta_compared = cmp_bytes(attr->img_hash, qta_baseval->valueinfo[0], HASH_SIZE);
        }
        break;
    case 2:
        printf("%s\n", "Compare hash measurement..");
        compared = cmp_bytes(report->hash, basevalue->valueinfo[1], HASH_SIZE);
        if (is_container) {
            qta_compared = cmp_bytes(attr->mem_hash, qta_baseval->valueinfo[1], HASH_SIZE);
        }
        break;
    case 3:
        printf("%s\n", "Compare image & hash measurement..");
        compared = (cmp_bytes(report->image_hash, basevalue->valueinfo[0], HASH_SIZE) &
                    cmp_bytes(report->hash, basevalue->valueinfo[1], HASH_SIZE));
        if (is_container) {
            qta_compared = (cmp_bytes(attr->img_hash, qta_baseval->valueinfo[0], HASH_SIZE) &
                            cmp_bytes(attr->mem_hash, qta_baseval->valueinfo[1], HASH_SIZE));
        }
        break;
    default:
        printf("%s\n", "Type is incorrect.");
        compared = false;
    }

    printf("%s\n", "Finish Comparation");
    return compared && qta_compared;
}

bool cmp_bytes(const uint8_t *a, const uint8_t *b, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (*(a + i) != *(b + i))
            return false;
    }

    return true;
}

void save_basevalue(const base_value *bv)
{
    // char **temp = (char **)malloc(sizeof(char*) * 3);
    // temp[0] = (char *)malloc(sizeof(char) * (32+4));
    // temp[1] = (char *)malloc(sizeof(char) * 64);
    // temp[2] = (char *)malloc(sizeof(char) * 64);
    char uuid_str[37];
    char image_hash_str[65];
    char hash_str[65];
    memset(uuid_str, '\0', sizeof(uuid_str));
    memset(image_hash_str, '\0', sizeof(image_hash_str));
    memset(hash_str, '\0', sizeof(hash_str));

    uuid_to_str(bv->uuid, uuid_str);
    hash_to_str(bv->valueinfo[0], image_hash_str);
    hash_to_str(bv->valueinfo[1], hash_str);

    const int bvbuf_len = 200;
    char bvbuf[bvbuf_len]; // 32+4+2+64+64+1=167 < 200
    memset(bvbuf, '\0', sizeof(bvbuf));
    strcpy(bvbuf, uuid_str);
    strcat(bvbuf, " ");
    strcat(bvbuf, image_hash_str);
    strcat(bvbuf, " ");
    strcat(bvbuf, hash_str);
    strcat(bvbuf, "\n");
    printf("%s\n", bvbuf);

    FILE *fp_output = fopen("basevalue.txt", "w");
    fwrite(bvbuf, strnlen(bvbuf, sizeof(bvbuf)), 1, fp_output);
    fclose(fp_output);
}

bool tee_verify_nonce(buffer_data *buf_data, buffer_data *nonce)
{
    if (nonce == NULL || nonce->size > USER_DATA_SIZE) {
        printf("the nonce-value is invalid\n");
        return false;
    }
    TA_report *report;
    report = Convert(buf_data);
    if (report == NULL) {
        printf("failed to parse the report\n");
        return false;
    }

    uint8_t tmp[64] = {0};
    bool vn = false;

    if (nonce->size > sizeof(report->nonce)) {
        printf("nonce length error, verify nonce failed.\n");
        free_report(report);
        return false;
    } else { // nonce->size <= sizeof(report->nonce)
        memcpy(tmp, nonce->buf, nonce->size);
    }

    // vn = cmp_bytes(report->nonce, nonce->buf, nonce->size);
    vn = cmp_bytes(report->nonce, tmp, sizeof(report->nonce));

    free_report(report);
    return vn;
}

int tee_verify_report(buffer_data *buf_data, buffer_data *nonce, container_info *info, int type, char *filename)
{
    bool vn = tee_verify_nonce(buf_data, nonce);
    if (vn == false) {
        return TVS_VERIFIED_NONCE_FAILED;
    }
    bool vs = tee_verify_signature(buf_data);
    if (vs == false) {
        return TVS_VERIFIED_SIGNATURE_FAILED;
    }
    bool v = tee_verify(buf_data, info, type, filename);
    if (v == false) {
        return TVS_VERIFIED_HASH_FAILED;
    }
    return TVS_ALL_SUCCESSED;
}

bool tee_verify2(buffer_data *bufdata, int type, base_value *baseval)
{
    TA_report *report = Convert(bufdata);

    bool verified;
    if ((report == NULL) || (baseval == NULL)) {
        printf("%s\n", "Pointer Error!");
        verified = false;
    } else
        verified = Compare(type, report,
                           baseval, NULL); // compare the report with the basevalue

    free_report(report);
    return verified;
}

int tee_validate_report(buffer_data *buf_data, buffer_data *nonce)
{
    bool vn = tee_verify_nonce(buf_data, nonce);
    if (vn == false) {
        return TVS_VERIFIED_NONCE_FAILED;
    }

    bool vs = tee_verify_signature(buf_data);
    if (vs == false) {
        return TVS_VERIFIED_SIGNATURE_FAILED;
    }

    return TVS_ALL_SUCCESSED;
}

int tee_validate_report2(buffer_data *buf_data, buffer_data *nonce)
{
    // bypass nonce verification
    bool vs = tee_verify_signature(buf_data);
    if (vs == false) {
        return TVS_VERIFIED_SIGNATURE_FAILED;
    }

    return TVS_ALL_SUCCESSED;
}

int tee_verify_report2(buffer_data *buf_data, int type, base_value *baseval)
{
    bool v = tee_verify2(buf_data, type, baseval);
    if (v == false) {
        return TVS_VERIFIED_HASH_FAILED;
    }
    return TVS_ALL_SUCCESSED;
}

static base_value *LoadQTABaseValue(const char *refval)
{
    base_value *baseval = (base_value *)calloc(1, sizeof(base_value));
    if (baseval == NULL)
        return NULL;

    char image_hash_str[65];
    char hash_str[65];
    if (EOF == sscanf(refval, "%64s %64s", image_hash_str, hash_str)) {
        free(baseval);
        return NULL;
    }
    str_to_hash(image_hash_str, baseval->valueinfo[0]);
    str_to_hash(hash_str, baseval->valueinfo[1]);
    return baseval;
}

static base_value *get_qta(buffer_data *akcert)
{
    if (akcert->buf == NULL) {
        printf("akcert is null");
        return NULL;
    }
    cJSON *pljson = NULL;
    cJSON *qimgjson = NULL;
    cJSON *qmemjson = NULL;
    buffer_data qimg;
    buffer_data qmem;
    base_value *qta = (base_value *)calloc(1, sizeof(base_value));
    if (qta == NULL) {
        return NULL;
    }
    // parse akcert
    cJSON *cj = cJSON_Parse(akcert->buf);
    if (cj == NULL) {
        printf("cjson parse akcert error");
        goto err1;
    }
    // get payload
    pljson = cJSON_GetObjectItemCaseSensitive(cj, "payload");
    if (pljson == NULL) {
        printf("cjson parse akcert error");
        goto err2;
    }
    // get qta_img, qta_mem
    qimgjson = cJSON_GetObjectItemCaseSensitive(pljson, "qta_img");
    qmemjson = cJSON_GetObjectItemCaseSensitive(pljson, "qta_mem");
    if (qimgjson == NULL || qmemjson == NULL) {
        printf("cjson parse akcert error");
        goto err2;
    }
    /*
       "qta_img": BASE64_TYPE, BASE64 of TA's img hash
         "qta_mem": BASE64_TYPE, BASE64 of TA's mem hash
    */
    // str2uint8(qimgjson->valuestring, strlen(qimgjson->valuestring)/2, qimgtmp);

    qimg.buf = base64urldecode(qimgjson->valuestring, strlen(qimgjson->valuestring), &qimg.size);
    // str2uint8(qmemjson->valuestring, strlen(qmemjson->valuestring)/2, qmemtmp);
    qmem.buf = base64urldecode(qmemjson->valuestring, strlen(qmemjson->valuestring), &qmem.size);
    memcpy(qta->valueinfo[0], qimg.buf, qimg.size);
    memcpy(qta->valueinfo[1], qmem.buf, qmem.size);

    if (qimg.buf != NULL)
        free(qimg.buf);
    if (qmem.buf != NULL)
        free(qmem.buf);

    cJSON_Delete(cj);
    return qta;

err2:
    cJSON_Delete(cj);
err1:
    free(qta);
    return NULL;
}

static bool CompareBV(int type, base_value *value, base_value *basevalue)
{
    bool compared;
    switch (type) {
    case 1:
        printf("%s\n", "Compare image measurement..");
        compared = cmp_bytes(value->valueinfo[0], basevalue->valueinfo[0], HASH_SIZE);
        break;
    case 2:
        printf("%s\n", "Compare hash measurement..");
        compared = cmp_bytes(value->valueinfo[1], basevalue->valueinfo[1], HASH_SIZE);
        break;
    case 3:
        printf("%s\n", "Compare image & hash measurement..");
        compared = cmp_bytes(value->valueinfo[0], basevalue->valueinfo[0], HASH_SIZE) &&
                   cmp_bytes(value->valueinfo[1], basevalue->valueinfo[1], HASH_SIZE);
        break;
    default:
        printf("%s\n", "Type is incorrect.");
        compared = false;
    }

    printf("%s\n", "Finish Comparation");
    return compared;
}

static bool verify_qta(buffer_data *akcert, int type, const char *refval)
{
    base_value *qta_val = get_qta(akcert);
    base_value *baseval = LoadQTABaseValue(refval);

    bool verified = false;
    if ((qta_val == NULL) || (baseval == NULL))
        printf("Pointer Error!\n");
    else
        verified = CompareBV(type, qta_val, baseval);

    free(qta_val);
    free(baseval);
    return verified;
}

bool tee_verify_akcert(buffer_data *akcert, int type, const char *refval)
{
    buffer_data datadrk, signdrk, certdrk, akpub;
    bool rt = false;

    rt = getDataFromAkCert(akcert, &datadrk, &signdrk, &certdrk, &akpub);
    if (!rt) {
        printf("failed to get data from ak cert!\n");
        goto err;
    }

    // verify the integrity of data in drk issued cert
    rt = verifysig_x509cert(&datadrk, &signdrk, &certdrk, NULL);
    if (!rt) {
        printf("validate ak cert failed!\n");
        goto err;
    }

    rt = verify_qta(akcert, type, refval);
    if (!rt) {
        printf("validate ak cert failed, qta verify error!\n");
        goto err;
    }

err:
    if (datadrk.buf != NULL)
        free(datadrk.buf);
    if (signdrk.buf != NULL)
        free(signdrk.buf);
    if (certdrk.buf != NULL)
        free(certdrk.buf);
    if (akpub.buf != NULL)
        free(akpub.buf);
    return rt;
}

bool tee_get_akcert_data(buffer_data *akcert, buffer_data *akpub, buffer_data *drkcrt)
{
    buffer_data datadrk, signdrk;
    bool rt = getDataFromAkCert(akcert, &datadrk, &signdrk, drkcrt, akpub);
    if (!rt) {
        printf("failed to get data from ak cert!\n");
    }

    if (datadrk.buf != NULL)
        free(datadrk.buf);
    if (signdrk.buf != NULL)
        free(signdrk.buf);
    return rt;
}
