#include "teeverifier.h"
#include "common.h"
#include "pair_FP256BN.h"

#define _SHA256(d, n, md)        \
   {                             \
      SHA256_CTX ctx;            \
      SHA256_Init(&ctx);         \
      SHA256_Update(&ctx, d, n); \
      SHA256_Final(md, &ctx);    \
   }

static void error(const char *msg);
static void file_error(const char *s);
static TA_report *Convert(buffer_data *buf_data);
// static void parse_uuid(uint8_t *uuid, TEE_UUID buf_uuid);
static void read_bytes(void *input, size_t size, size_t nmemb,
                       uint8_t *output, size_t *offset);
static base_value *LoadBaseValue(const TA_report *report, char *filename);
static void str_to_uuid(const char *str, uint8_t *uuid);
static void uuid_to_str(const uint8_t *uuid, char *str);
static void str_to_hash(const char *str, uint8_t *hash);
static void hash_to_str(const uint8_t *hash, char *str);
static void hex2str(const uint8_t *source, int source_len, char *dest);
static void str2hex(const char *source, int source_len, uint8_t *dest);
static char *file_to_buffer(char *file, size_t *file_length);
static bool Compare(int type, TA_report *report, base_value *basevalue);
static bool cmp_bytes(const uint8_t *a, const uint8_t *b, size_t size);
static void free_report(TA_report *report);
static void test_print(uint8_t *printed, int printed_size,
                       char *printed_name);
static void save_basevalue(const base_value *bv);

// signature part
bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *cert,
               uint32_t scenario);
static bool translateBuf(buffer_data report, TA_report *tareport);
static EVP_PKEY *buildPubKeyFromModulus(buffer_data *pub);
static EVP_PKEY *getPubKeyFromDrkIssuedCert(buffer_data *cert);
static bool verifySigByKey(buffer_data *mhash, buffer_data *sign,
                           EVP_PKEY *key);
static EVP_PKEY *getPubKeyFromCert(buffer_data *cert);
static void dumpDrkCert(buffer_data *certdrk);
static void restorePEMCert(uint8_t *data, int data_len, buffer_data *certdrk);
static bool getDataFromReport(buffer_data *report, buffer_data *akcert,
                              buffer_data *signak, buffer_data *signdata,
                              uint32_t *scenario);
bool getDataFromAkCert(buffer_data *akcert, buffer_data *signdata,
                       buffer_data *signdrk, buffer_data *certdrk,
                       buffer_data *akpub);

EVP_PKEY *
buildPubKeyFromModulus(buffer_data *pub)
{
   EVP_PKEY *key = NULL;
   key = EVP_PKEY_new();

   BIGNUM *e = BN_new();
   BN_set_word(e, 0x10001);
   BIGNUM *n = BN_new();
   BN_bin2bn(pub->buf, pub->size, n);

   RSA *rsapub = RSA_new();
   RSA_set0_key(rsapub, n, e, NULL);

   EVP_PKEY_set1_RSA(key, rsapub);

   return key;
}

EVP_PKEY *
getPubKeyFromDrkIssuedCert(buffer_data *cert)
{
   buffer_data datadrk, signdrk, certdrk, akpub;
   bool rt;
   EVP_PKEY *key = NULL;

   rt = getDataFromAkCert(cert, &datadrk, &signdrk, &certdrk, &akpub);
   if (!rt)
   {
      printf("get NOAS data is failed!\n");
      return false;
   }

   // verify the integrity of data in drk issued cert
   rt = verifysig(&datadrk, &signdrk, &certdrk, 1);
   if (!rt)
   {
      printf("validate drk cert failed!\n");
      return NULL;
   }

   // build a pub key with the modulus carried in drk issued cert
   key = buildPubKeyFromModulus(&akpub);
   return key;
}

bool verifySigByKey(buffer_data *mhash, buffer_data *sign, EVP_PKEY *key)
{
   if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA)
   {
      printf("the pub key type is not in supported type list(rsa)\n");
      return false;
   }

   uint8_t buf[512];
   int rt = RSA_public_decrypt(sign->size, sign->buf, buf,
                               EVP_PKEY_get1_RSA(key), RSA_NO_PADDING);
   if (rt == -1)
   {
      printf("RSA public decrypt is failed with error %s\n",
             ERR_error_string(ERR_get_error(), NULL));
      return false;
   }

   // rt = RSA_verify_PKCS1_PSS_mgf1(EVP_PKEY_get1_RSA(key), mhash->buf,
   // EVP_sha256(), EVP_sha256(), buf, -2);
   rt = RSA_verify_PKCS1_PSS(EVP_PKEY_get1_RSA(key), mhash->buf,
                             EVP_sha256(), buf, -2);
   // rt = RSA_verify(EVP_PKEY_RSA_PSS, mhash->buf, SHA256_DIGEST_LENGTH,
   // signdrk.buf, signdrk.size, EVP_PKEY_get1_RSA(key));
   if (rt != 1)
   {
      printf("verify sign is failed with error %s\n",
             ERR_error_string(ERR_get_error(), NULL));
      return false;
   }

   return true;
}

EVP_PKEY *
getPubKeyFromCert(buffer_data *cert)
{
   EVP_PKEY *key = NULL;
   X509 *c = NULL;

   BIO *bp = BIO_new_mem_buf(cert->buf, cert->size);
   if ((c = PEM_read_bio_X509(bp, NULL, NULL, NULL)) == NULL)
   {
      printf("failed to get drkcert x509\n");
      return NULL;
   }

   key = X509_get_pubkey(c);
   if (key == NULL)
   {
      printf("Error getting public key from certificate");
   }

   return key;
}

static bool
verifydatasig_bykey(buffer_data *data, buffer_data *sign, EVP_PKEY *key)
{
   // caculate the digest of the data
   uint8_t digest[SHA256_DIGEST_LENGTH];
   _SHA256(data->buf, data->size, digest);

   // perform signature verification
   buffer_data mhash = {sizeof(digest), digest};
   bool rt = verifySigByKey(&mhash, sign, key);

   return rt;
}

static bool
verifysig_drksignedcert(buffer_data *data, buffer_data *sign,
                        buffer_data *cert)
{
   // get the key for signature verification
   EVP_PKEY *key = getPubKeyFromDrkIssuedCert(cert);
   if (key == NULL)
      return false;

   bool rt = verifydatasig_bykey(data, sign, key);
   EVP_PKEY_free(key);

   return rt;
}

static bool
verifysig_x509cert(buffer_data *data, buffer_data *sign, buffer_data *cert)
{
   // get the key for signature verification
   EVP_PKEY *key = getPubKeyFromCert(cert);
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

typedef struct
{
   ECP_FP256BN *a;
   ECP_FP256BN *b;
   ECP_FP256BN *c;
   ECP_FP256BN *d;
} daa_ak_cert;

typedef struct
{
   BIG_256_56 h2;
   BIG_256_56 s;
   BIG_256_56 nm;
   ECP_FP256BN *j;
   ECP_FP256BN *k;
} daa_signature;

typedef struct
{
   ECP2_FP256BN *x;
   ECP2_FP256BN *y;
} daa_pub;

static int
hex2bin_append(const char *hexbuf, size_t *offset, size_t buflen, octet *oct)
{
   char *p = strchr(hexbuf + *offset, '\n');
   if (p == NULL)
      return 0;

   if (p - hexbuf - *offset != 64)
      return 0;

   if (oct->len + 32 > oct->max)
      return 0;

   str2hex(hexbuf + *offset, 32, oct->val + oct->len);

   *offset += 64 + 1;
   oct->len += 32;
   return 32;
}

static ECP2_FP256BN *
get_p2_from_fbuf(char *buf, size_t *offset, size_t buflen)
{
   ECP2_FP256BN *pt = malloc(sizeof(ECP2_FP256BN));
   if (pt == NULL)
      goto err1;
   uint8_t val[32 * 4 + 1];
   octet oct = {0, sizeof(val), val};

   val[0] = 0x04;
   oct.len = 1;
   int i;
   for (i = 0; i < 4; i++)
   {
      if (32 != hex2bin_append(buf, offset, buflen, &oct))
         goto err2;
   }

   FP2_FP256BN x, y;
   BIG_256_56 x0, x1, y0, y1;
   BIG_256_56_fromBytes(x0, oct.val+1);
   BIG_256_56_fromBytes(x1, oct.val+1+32);
   BIG_256_56_fromBytes(y0, oct.val+1+64);
   BIG_256_56_fromBytes(y1, oct.val+1+96);
   FP2_FP256BN_from_BIGs(&x, x0, x1);
   FP2_FP256BN_from_BIGs(&y, y0, y1);
   ECP2_FP256BN_set(pt, &x, &y);
   //ECP2_FP256BN_fromOctet(pt, &oct);

   return pt;

err2:
   free(pt);
err1:
   return NULL;
}

static void
free_daa_pub(daa_pub *pub)
{
   if (pub == NULL)
      return;

   if (pub->x != NULL)
      free(pub->x);
   if (pub->y != NULL)
      free(pub->y);
   free(pub);
}

static daa_pub *
daa_get_issuer_pub()
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

static void
free_p1(ECP_FP256BN *p1)
{
   if (p1 == NULL)
      return;

   free(p1);
}

static int
unmarshal_bn_from_bd(BIG_256_56 bn, buffer_data *bd, uint32_t *offset)
{
   if (*offset >= bd->size || *offset + 0x24 > bd->size)
      goto err1;

   uint32_t size = 0;
   memcpy((void *)&size, bd->buf + *offset, sizeof(uint32_t));
   if (size != 0x20)
      goto err1;
   *offset += sizeof(uint32_t);
   BIG_256_56_fromBytes(bn, bd->buf + *offset);
   *offset += size;

   return 1;

err1:
   return 0;
}

static ECP_FP256BN *
unmarshal_p1_from_bd(buffer_data *bd, uint32_t *offset)
{
   if (*offset >= bd->size || *offset + 0x4c > bd->size)
      goto err1;

   ECP_FP256BN *p1 = malloc(sizeof(ECP_FP256BN));
   if (p1 == NULL)
      goto err1;

   uint32_t size = 0;
   memcpy((void *)&size, bd->buf + *offset, sizeof(uint32_t));
   *offset += sizeof(uint32_t);
   if (size != 0x48)
      goto err2;
   BIG_256_56 x, y;
   if (unmarshal_bn_from_bd(x, bd, offset) == 0)
      goto err2;
   if (unmarshal_bn_from_bd(y, bd, offset) == 0)
      goto err2;

   if (0 == ECP_FP256BN_set(p1, x, y))
      goto err2;

   return p1;

err2:
   free_p1(p1);
err1:
   return NULL;
}

static void
free_daa_ak_cert(daa_ak_cert *cert)
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

static daa_ak_cert *
unmarshal_daa_ak_cert(buffer_data *cert)
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

static void
free_daa_signature(daa_signature *sign)
{
   if (sign == NULL)
      return;

   if (sign->j != NULL)
      free(sign->j);
   if (sign->k != NULL)
      free(sign->k);
   free(sign);
}

static daa_signature *
unmarshal_daa_signature(buffer_data *sign)
{
   daa_signature *sig = malloc(sizeof(daa_signature));
   if (sig == NULL)
      goto err1;

   sig->j = NULL;
   sig->k = NULL;

   uint32_t offset = 0;
   sig->j = unmarshal_p1_from_bd(sign, &offset);
   sig->k = unmarshal_p1_from_bd(sign, &offset);
   if (unmarshal_bn_from_bd(sig->h2, sign, &offset) == 0)
      goto err2;
   if (unmarshal_bn_from_bd(sig->s, sign, &offset) == 0)
      goto err2;
   if (unmarshal_bn_from_bd(sig->nm, sign, &offset) == 0)
      goto err2;

   return sig;

err2:
   free_daa_signature(sig);
err1:
   return NULL;
}

static bool
verify_daacert(daa_ak_cert *cert)
{
   bool rt = false;
   daa_pub *ispubkey = daa_get_issuer_pub();
   if (ispubkey == NULL)
      goto err1;

   ECP2_FP256BN p2;
   ECP2_FP256BN_generator(&p2);

   FP12_FP256BN lhs, rhs;

   PAIR_FP256BN_ate(&lhs, ispubkey->y, cert->a);
   PAIR_FP256BN_fexp(&lhs);

   PAIR_FP256BN_ate(&rhs, &p2, cert->b);
   PAIR_FP256BN_fexp(&rhs);

   if (!FP12_FP256BN_equals(&lhs, &rhs))
      goto err2;

   ECP_FP256BN ptemp;

   ECP_FP256BN_copy(&ptemp, cert->d);
   ECP_FP256BN_add(&ptemp, cert->a);
   PAIR_FP256BN_ate(&lhs, ispubkey->x, &ptemp);
   PAIR_FP256BN_fexp(&lhs);

   PAIR_FP256BN_ate(&rhs, &p2, cert->c);
   PAIR_FP256BN_fexp(&rhs);

   if (!FP12_FP256BN_equals(&lhs, &rhs))
      goto err2;

   rt = true;

err2:
   free_daa_pub(ispubkey);
err1:
   return rt;
}

static void hash_update_buf(SHA256_CTX *ctx, char *buf, int size)
{
   SHA256_Update(ctx, (char *)&size, sizeof(int));
   if (size > 0)
      SHA256_Update(ctx, buf, size);
}

static void hash_update_p1(SHA256_CTX *ctx, ECP_FP256BN *p1)
{
   BIG_256_56 x, y;
   char v_tmp[SHA256_DIGEST_LENGTH];
   int p1_size = 2 * (sizeof(v_tmp) + sizeof(int));

   ECP_FP256BN_get(x, y, p1);

   SHA256_Update(ctx, (char *)&p1_size, sizeof(int));
   BIG_256_56_toBytes(v_tmp, x);
   hash_update_buf(ctx, v_tmp, sizeof(v_tmp));
   BIG_256_56_toBytes(v_tmp, y);
   hash_update_buf(ctx, v_tmp, sizeof(v_tmp));
}

static bool
verify_daasig(buffer_data *mhash, daa_signature *sig, daa_ak_cert *cert)
{
   ECP_FP256BN l, e, s_j, h2_k, s_b, h2_d;

   // may need additional step to verify J while bsn is available
   // s1,y1=Hs(bsn); verify J=(Hp(s1),y1)

   // skip J, K, L caculation while J is null.
   if (sig->j != NULL)
   {
      ECP_FP256BN_copy(&s_j, sig->j);
      ECP_FP256BN_mul(&s_j, sig->s);
      ECP_FP256BN_copy(&h2_k, sig->k);
      ECP_FP256BN_mul(&h2_k, sig->h2);
      ECP_FP256BN_copy(&l, &s_j);
      ECP_FP256BN_sub(&l, &h2_k);
   }

   ECP_FP256BN_copy(&s_b, cert->b);
   ECP_FP256BN_mul(&s_b, sig->s);
   ECP_FP256BN_copy(&h2_d, cert->d);
   ECP_FP256BN_mul(&h2_d, sig->h2);
   ECP_FP256BN_copy(&e, &s_b);
   ECP_FP256BN_sub(&e, &h2_d);

   // calculate c=H(H(m),A,B,C,D,J,K,L,E))
   SHA256_CTX ctx;
   SHA256_Init(&ctx);
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
   if (sig->j != NULL)
   {
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

   uint8_t c[SHA256_DIGEST_LENGTH];
   SHA256_Final(c, &ctx);

   octet tmp = {SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH, mhash->buf};

   // caclulate h1=H(c); h2=Hn(nm || h1)
   // uint8_t h1[SHA256_DIGEST_LENGTH];
   // _SHA256(c, sizeof(c), h1);

   SHA256_Init(&ctx);

   uint8_t nm[SHA256_DIGEST_LENGTH];
   BIG_256_56_toBytes(nm, sig->nm);
   hash_update_buf(&ctx, nm, sizeof(nm));
   // currently h1=c, so use c directly
   hash_update_buf(&ctx, c, sizeof(c));

   uint8_t h2[SHA256_DIGEST_LENGTH];
   SHA256_Final(h2, &ctx);

   BIG_256_56 b_h2, n;
   BIG_256_56_fromBytes(b_h2, h2);
   BIG_256_56_rcopy(n, CURVE_Order_FP256BN);
   BIG_256_56_mod(b_h2, n);

   if (BIG_256_56_comp(b_h2, sig->h2) != 0)
      return false;

   return true;
}

static bool
verifysig_daacert(buffer_data *data, buffer_data *sign, buffer_data *cert)
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
   uint8_t digest[SHA256_DIGEST_LENGTH];
   _SHA256(data->buf, data->size, digest);

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
bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *cert,
               uint32_t scenario)
{
   if (data->size <= 0 || sign->size <= 0 || cert->size <= 0 || scenario > 2)
   {
      return false;
   }

   switch (scenario)
   {
   case 0:
      return verifysig_drksignedcert(data, sign, cert);
   case 1:
      return verifysig_x509cert(data, sign, cert);
   case 2:
      return verifysig_daacert(data, sign, cert);
   }

   return false;
}

void dumpDrkCert(buffer_data *certdrk)
{
   FILE *f = fopen("drk.crt", "wb");
   if (!f)
   {
      fprintf(stderr, "unable to open: %s\n", "test.cert");
      return;
   }
   fwrite(certdrk->buf, sizeof(char), certdrk->size, f);
   fclose(f);
}

void restorePEMCert(uint8_t *data, int data_len, buffer_data *certdrk)
{
   uint8_t head[] = "-----BEGIN CERTIFICATE-----\n";
   uint8_t end[] = "-----END CERTIFICATE-----\n";
   uint8_t *drktest = (uint8_t *)malloc(sizeof(uint8_t) * 2048); // malloc a buffer big engough
   memcpy(drktest, head, strlen(head));

   uint8_t *src = data;
   uint8_t *dst = drktest + strlen(head);
   int loop = data_len / 64;
   int rem = data_len % 64;
   int i = 0;

   for (i = 0; i < loop; i++, src += 64, dst += 65)
   {
      memcpy(dst, src, 64);
      dst[64] = '\n';
   }
   if (rem > 0)
   {
      memcpy(dst, src, rem);
      dst[rem] = '\n';
      dst += rem + 1;
   }
   memcpy(dst, end, strlen(end));
   dst += strlen(end);
   certdrk->size = dst - drktest;
   certdrk->buf = drktest;

   // dumpDrkCert(certdrk);
}
// getDataFromReport get some data which have akcert & signak & signdata &
// scenario from report
bool getDataFromReport(buffer_data *report, buffer_data *akcert,
                       buffer_data *signak, buffer_data *signdata,
                       uint32_t *scenario)
{
   if (report->buf == NULL)
   {
      printf("report is null");
      return false;
   }
   struct report_response *re;
   re = (struct report_response *)report->buf;
   *scenario = re->scenario;
   uint32_t data_offset;
   uint32_t data_len;
   uint32_t param_count = re->param_count;
   if (param_count <= 0)
   {
      return false;
   }
   for (int i = 0; i < param_count; i++)
   {
      uint32_t param_info = re->params[i].tags;
      uint32_t param_type = (re->params[i].tags & 0xf0000000) >> 28; // get high 4 bits
      if (param_type == 2)
      {
         data_offset = re->params[i].data.blob.data_offset;
         data_len = re->params[i].data.blob.data_len;
         if (data_offset + data_len > report->size)
         {
            return false;
         }
         switch (param_info)
         {
         case RA_TAG_CERT_AK:
            akcert->buf = report->buf + data_offset;
            akcert->size = data_len;
            break;
         case RA_TAG_SIGN_AK:
            signak->buf = report->buf + data_offset;
            signak->size = data_len;
            // get sign data
            signdata->buf = report->buf;
            signdata->size = data_offset;
            break;
         default:
            break;
         }
      }
   }
   return true;
}
// get some data which have signdata signdrk certdrk and akpub from akcert
bool getDataFromAkCert(buffer_data *akcert, buffer_data *signdata,
                       buffer_data *signdrk, buffer_data *certdrk,
                       buffer_data *akpub)
{
   if (akcert->buf == NULL)
   {
      printf("akcert is null");
      return false;
   }
   struct ak_cert *ak;
   ak = (struct ak_cert *)akcert->buf;
   uint32_t data_offset;
   uint32_t data_len;
   uint32_t param_count = ak->param_count;

   if (param_count <= 0)
   {
      return false;
   }
   for (int i = 0; i < param_count; i++)
   {
      uint32_t param_info = ak->params[i].tags;
      uint32_t param_type = (ak->params[i].tags & 0xf0000000) >> 28; // get high 4 bits
      if (param_type == 2)
      {
         data_offset = ak->params[i].data.blob.data_offset;
         data_len = ak->params[i].data.blob.data_len;
         if (data_offset + data_len > akcert->size)
         {
            return false;
         }
         switch (param_info)
         {
         case RA_TAG_AK_PUB:
            akpub->buf = akcert->buf + data_offset;
            akpub->size = data_len;
            break;
         case RA_TAG_SIGN_DRK:
            signdrk->buf = akcert->buf + data_offset;
            signdrk->size = data_len;
            // get sign data
            signdata->size = data_offset; // signdrk 的offset之前都是被签名的数据
            signdata->buf = akcert->buf;
            break;
         case RA_TAG_CERT_DRK:
            restorePEMCert(akcert->buf + data_offset, data_len, certdrk);
            break;
         default:
            break;
         }
      }
   }
   return true;
}

bool tee_verify_signature(buffer_data *report)
{
   // get akcert signak signdata from report
   buffer_data akcert, signak, signdata;
   uint32_t scenario;
   bool rt = getDataFromReport(report, &akcert, &signak, &signdata, &scenario);
   if (!rt)
   {
      printf("get Data From Report is failed\n");
      return false;
   }
   rt = verifysig(&signdata, &signak, &akcert, scenario);
   if (!rt)
   {
      printf("verify signature is failed\n");
      return false;
   }
   printf("Verify success!\n");
   return true;
}

void error(const char *msg)
{
   printf("%s\n", msg);
   exit(EXIT_FAILURE);
}

void file_error(const char *s)
{
   printf("Couldn't open file: %s\n", s);
   exit(EXIT_FAILURE);
}

void test_print(uint8_t *printed, int printed_size, char *printed_name)
{
   printf("%s:\n", printed_name);
   for (int i = 0; i < printed_size; i++)
   {
      printf("%02X", printed[i]);
      if (i % 32 == 31)
      {
         printf("\n");
      }
   }
   printf("\n");
};

void free_report(TA_report *report)
{
   if (report->signature != NULL)
   {
      free(report->signature);
      report->signature = NULL;
   }
   if (report->cert != NULL)
   {
      free(report->cert);
      report->cert = NULL;
   }
};

bool tee_verify(buffer_data *bufdata, int type, char *filename)
{
   TA_report *report = Convert(bufdata);
   base_value *baseval = LoadBaseValue(report, filename);

   bool verified;
   if ((report == NULL) || (baseval == NULL))
   {
      printf("%s\n", "Pointer Error!");
      verified = false;
   }
   else
      verified = Compare(type, report,
                         baseval); // compare the report with the basevalue

   free_report(report);
   free(report);
   free(baseval);
   return verified;
}

TA_report *
Convert(buffer_data *data)
{
   TA_report *report = NULL;

   // determine whether the buffer is legal
   if (data == NULL)
      error("illegal buffer data pointer.");
   if (data->size > DATABUFMAX || data->size < DATABUFMIN)
      error("size of buffer is illegal.");

   report_get *bufreport;
   bufreport = (report_get *)data->buf; // buff to report

   report = (TA_report *)calloc(1, sizeof(TA_report));
   report->version = bufreport->version;
   report->timestamp = bufreport->ts;
   memcpy(report->nonce, bufreport->nonce, USER_DATA_SIZE * sizeof(uint8_t));
   memcpy(report->uuid, &(bufreport->uuid), UUID_SIZE * sizeof(uint8_t));
   // parse_uuid(report->uuid, bufreport->uuid);
   report->scenario = bufreport->scenario;
   // parse ra_params
   uint32_t param_count = bufreport->param_count;
   for (int i = 0; i < param_count; i++)
   {
      uint32_t param_type = (bufreport->params[i].tags & 0xf0000000) >> 28; // get high 4 bits
      uint32_t param_info = bufreport->params[i].tags;
      if (param_type == 1)
      {
         switch (param_info)
         {
         case RA_TAG_SIGN_TYPE:
            report->sig_alg = bufreport->params[i].data.integer;
            break;
         case RA_TAG_HASH_TYPE:
            report->hash_alg = bufreport->params[i].data.integer;
            break;
         default:
            error("Invalid param_info!");
         }
      }
      else if (param_type == 2)
      {
         uint32_t data_offset = bufreport->params[i].data.blob.data_offset;
         uint32_t data_len = bufreport->params[i].data.blob.data_len;

         if ((data_offset + data_len) > data->size || data_offset == 0)
         {
            char *error_msg = NULL;
            sprintf(error_msg, "2-%u offset error", param_info);
            error(error_msg);
         }

         switch (param_info)
         {
         case RA_TAG_TA_IMG_HASH:
            memcpy(report->image_hash, data->buf + data_offset, data_len);
            break;
         case RA_TAG_TA_MEM_HASH:
            memcpy(report->hash, data->buf + data_offset, data_len);
            break;
         case RA_TAG_RESERVED:
            memcpy(report->reserve, data->buf + data_offset, data_len);
            break;
         case RA_TAG_SIGN_AK:
            report->signature = (buffer_data *)malloc(sizeof(buffer_data));
            report->signature->buf = (uint8_t *)malloc(sizeof(uint8_t) * data_len);
            report->signature->size = data_len;
            memcpy(report->signature->buf, data->buf + data_offset,
                   data_len);
            // uint32_t cert_offset = data_offset + data_len +
            // sizeof(uint32_t); memcpy(report->cert, data->buf+cert_offset,
            // data_len);
            break;
         case RA_TAG_CERT_AK:
            report->cert = (buffer_data *)malloc(sizeof(buffer_data));
            report->cert->buf = (uint8_t *)malloc(sizeof(uint8_t) * data_len);
            report->cert->size = data_len;
            memcpy(report->cert->buf, data->buf + data_offset, data_len);
            break;
         default:
            error("Invalid param_info!");
         }
      }
      else
         error("Invalid param_type!");
   }

   return report;
}

// void parse_uuid(uint8_t *uuid, TEE_UUID bufuuid) {
//     size_t offset = 0;

//     read_bytes(&(bufuuid.timeLow), sizeof(uint32_t), 1, uuid, &offset);
//     read_bytes(&(bufuuid.timeMid), sizeof(uint16_t), 1, uuid, &offset);
//     read_bytes(&(bufuuid.timeHiAndVersion), sizeof(uint16_t), 1, uuid,
//     &offset); read_bytes(&(bufuuid.clockSeqAndNode), sizeof(uint8_t),
//     NODE_LEN, uuid, &offset);
// }

void read_bytes(void *input, size_t size, size_t nmemb, uint8_t *output,
                size_t *offset)
{
   memcpy(output + *offset, input, size * nmemb);
   *offset += size * nmemb;
}

base_value *
LoadBaseValue(const TA_report *report, char *filename)
{
   base_value *baseval = NULL;
   size_t fbuf_len = 0; // if needed

   if (report == NULL)
      error("illegal report pointer!");
   char *fbuf = file_to_buffer(filename, &fbuf_len);

   /*
      base_value *baseval_tmp = NULL;
      size_t fbuf_offset = 0;
      while(fbuf_offset < fbuf_len) {
         baseval_tmp = (base_value *)(fbuf+fbuf_offset);
         if (cmp_bytes(report->uuid, baseval_tmp->uuid, UUID_SIZE)) break;
         fbuf_offset += sizeof(base_value);
      }

      baseval = (base_value *)calloc(1, sizeof(base_value));
      memcpy(baseval->uuid, baseval_tmp->uuid, UUID_SIZE*sizeof(uint8_t));
      memcpy(baseval->valueinfo[0], baseval_tmp->valueinfo[0],
   HASH_SIZE*sizeof(uint8_t)); memcpy(baseval->valueinfo[1],
   baseval_tmp->valueinfo[1], HASH_SIZE*sizeof(uint8_t));

      baseval_tmp = NULL;
   **/

   // fbuf is string stream.
   char *line = NULL;
   line = strtok(fbuf, "\n");

   baseval = (base_value *)calloc(1, sizeof(base_value));
   char uuid_str[37];
   char image_hash_str[65];
   char hash_str[65];
   int num = 0;
   while (line != NULL)
   {
      ++num;
      sscanf(line, "%36s %64s %64s", uuid_str, image_hash_str, hash_str);
      str_to_uuid(uuid_str, baseval->uuid);
      if (cmp_bytes(report->uuid, baseval->uuid, UUID_SIZE))
      {
         str_to_hash(image_hash_str, baseval->valueinfo[0]);
         str_to_hash(hash_str, baseval->valueinfo[1]);
         break;
      }

      line = strtok(NULL, "\n");
   }

   free(fbuf);
   return baseval;
}

void reverse(uint8_t *bytes, int size)
{
   for (int i = 0; i < size / 2; i++)
   {
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
   sscanf(str, "%8[^-]-%4[^-]-%4[^-]-%4[^-]-%12[^-]", substr1, substr2,
          substr3, substr4, substr5);
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

   for (i = 0; i < source_len; i++)
   {
      HighByte = source[i] >> 4;  // get high 4bit from a byte
      LowByte = source[i] & 0x0f; // get low 4bit

      HighByte += 0x30;     // Get the corresponding char, and skip 7 symbols if
                            // it's a letter
      if (HighByte <= 0x39) // number
         dest[i * 2] = HighByte;
      else                              // letter
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

   for (i = 0; i < source_len; i++)
   {
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

char *
file_to_buffer(char *file, size_t *file_length)
{
   FILE *f = NULL;
   char *buffer = NULL;

   f = fopen(file, "rb");
   if (!f)
      file_error(file);
   fseek(f, 0L, SEEK_END);
   *file_length = ftell(f);
   rewind(f);
   buffer = (char *)malloc(*file_length + 1);
   size_t result = fread(buffer, 1, *file_length, f);
   if (result != *file_length)
      file_error(file);
   fclose(f);

   return buffer;
}

bool Compare(int type, TA_report *report, base_value *basevalue)
{
   bool compared;
   /*
      test_print(report->image_hash, HASH_SIZE, "report->image_hash");
      test_print(report->hash, HASH_SIZE, "report->hash");
      test_print(basevalue->valueinfo[0], HASH_SIZE, "basevalue->valueinfo[0]");
      test_print(basevalue->valueinfo[1], HASH_SIZE, "basevalue->valueinfo[1]");
      test_print(report->uuid, 16, "report->uuid");
      test_print(basevalue->uuid, 16, "basevalue->uuid");
   */
   switch (type)
   {
   case 1:
      printf("%s\n", "Compare image measurement..");
      compared = cmp_bytes(report->image_hash, basevalue->valueinfo[0], HASH_SIZE);
      break;
   case 2:
      printf("%s\n", "Compare hash measurement..");
      compared = cmp_bytes(report->hash, basevalue->valueinfo[1], HASH_SIZE);
      break;
   case 3:
      printf("%s\n", "Compare image & hash measurement..");
      compared = (cmp_bytes(report->image_hash, basevalue->valueinfo[0], HASH_SIZE) & cmp_bytes(report->hash, basevalue->valueinfo[1], HASH_SIZE));
      break;
   default:
      printf("%s\n", "Type is incorrect.");
      compared = false;
   }

   printf("%s\n", "Finish Comparation");
   return compared;
}

bool cmp_bytes(const uint8_t *a, const uint8_t *b, size_t size)
{
   for (size_t i = 0; i < size; i++)
   {
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
   if (nonce == NULL || nonce->size > USER_DATA_SIZE)
   {
      printf("%s\n", "the nonce-value is invalid");
      return false;
   }
   TA_report *report;
   report = Convert(buf_data);
   bool vn = cmp_bytes(report->nonce, nonce->buf, nonce->size);
   return vn;
}

int tee_verify_report(buffer_data *buf_data, buffer_data *nonce, int type,
                      char *filename)
{
   bool vn = tee_verify_nonce(buf_data, nonce);
   if (vn == false)
   {
      return TVS_VERIFIED_NONCE_FAILED;
   }
   bool vs = tee_verify_signature(buf_data);
   if (vs == false)
   {
      return TVS_VERIFIED_SIGNATURE_FAILED;
   }
   bool v = tee_verify(buf_data, type, filename);
   if (v == false)
   {
      return TVS_VERIFIED_HASH_FAILED;
   }
   return TVS_ALL_SUCCESSED;
}
