#include "verifier.h"
#include "common.h"

static void error(const char *msg);
static void file_error(const char *s);
static TA_report *Convert(buffer_data *buf_data);
// static void parse_uuid(uint8_t *uuid, TEE_UUID buf_uuid);
static void read_bytes(void *input, size_t size, size_t nmemb, uint8_t *output, size_t *offset);
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
static void test_print(uint8_t *printed, int printed_size, char *printed_name);
static void save_basevalue(const base_value *bv);

// interface
bool VerifySignature(buffer_data *report);

bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *akcert, int scenario);
bool translateBuf(buffer_data report, TA_report *tareport);
bool getNOASdata(buffer_data *akcert, buffer_data *signdata, buffer_data *signdrk, buffer_data *certdrk, buffer_data *akpub);
// testSignature will generate a signature by the private_key.pem file
void testSignature(char *digest, char *sig)
{
   char buf[256] = {0};
   // get private key from file
   FILE *fp = fopen(PRIVATEKEY, "r");
   if (fp == NULL)
   {
      printf("read file failed\n");
   }
   RSA *privKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
   if (privKey == NULL)
   {
      printf("failed get private key\n");
   }
   fclose(fp);
   int nOutLen = strlen(sig);
   int rt = 0;
   rt = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, sig, &nOutLen, privKey);
   if (rt != 1)
   {
      printf("sig failed\n");
   }
}

EVP_PKEY *buildPubKeyFromModulus(buffer_data *pub)
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

EVP_PKEY *getPubKeyFromDrkIssuedCert(buffer_data *cert)
{
   buffer_data datadrk, signdrk, certdrk, akpub;
   bool rt;
   EVP_PKEY *key = NULL;

   rt = getNOASdata(cert, &datadrk, &signdrk, &certdrk, &akpub);
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
   int rt = RSA_public_decrypt(sign->size, sign->buf, buf, EVP_PKEY_get1_RSA(key), RSA_NO_PADDING);
   if (rt == -1)
   {
      printf("RSA public decrypt is failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
      return false;
   }

   // rt = RSA_verify_PKCS1_PSS_mgf1(EVP_PKEY_get1_RSA(key), mhash->buf, EVP_sha256(), EVP_sha256(), buf, -2);
   rt = RSA_verify_PKCS1_PSS(EVP_PKEY_get1_RSA(key), mhash->buf, EVP_sha256(), buf, -2);
   // rt = RSA_verify(EVP_PKEY_RSA_PSS, mhash->buf, SHA256_DIGEST_LENGTH, signdrk.buf, signdrk.size, EVP_PKEY_get1_RSA(key));
   if (rt != 1)
   {
      printf("verify sign is failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
      return false;
   }

   return true;
}

EVP_PKEY *getPubKeyFromCert(buffer_data *cert)
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

/*
verifysig will verify the signature in report
   data: data protected by signature, a byte array
   sign: the signature, a byte array
   cert: a byte array.
      A drk signed cert in self-defined format for scenario 0;
      A X509 PEM cert for scenario 1.
   scenario: 0 or 1. refer to the description above.
   return value: true if the sigature verification succeeded, else false.
*/
bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *cert, int scenario)
{
   if (data->size <= 0 || sign->size <= 0 || cert->size <= 0 || scenario < 0 || scenario > 1)
   {
      return false;
   }

   // step 1: handle the cert per scenario to get the key for signature verification
   EVP_PKEY *key = NULL;
   switch (scenario)
   {
   case 0:
      // handle drk issued cert, with customized format
      key = getPubKeyFromDrkIssuedCert(cert);
      break;
   case 1:
      // handle normal PEM cert
      key = getPubKeyFromCert(cert);
      break;
   default:
      return false;
   }
   if (key == NULL)
   {
      return false;
   }

   // step 2: caculate the digest of the data
   uint8_t digest[SHA256_DIGEST_LENGTH];
   SHA256(data->buf, data->size, digest);

   // step 3 : perform signature verification
   buffer_data mhash = {sizeof(digest), digest};
   bool rt = verifySigByKey(&mhash, sign, key);

   EVP_PKEY_free(key);
   return rt;

   return true;
}

// translateBuf will translate the buffer_date to TAreport
bool translateBuf(buffer_data report, TA_report *tareport)
{
   memcpy(tareport, report.buf, report.size);
   return true;
}

// getAkSignFromReport will get the sign_ak[] from report's buffer
bool getAkSignFromReport(buffer_data *report, buffer_data *out)
{
   if (report->buf == NULL)
   {
      printf("report is null");
      return false;
   }
   struct report_response *rr = (struct report_response *)report->buf;
   out->buf = report->buf + rr->params[5].data.blob.data_offset;
   out->size = rr->params[5].data.blob.data_len;

   return true;
}

// getAkCertFromReport will get the akcert[] from report's buffer
bool getAkCertFromReport(buffer_data *report, buffer_data *out)
{
   if (report->buf == NULL)
   {
      printf("report is null");
      return false;
   }
   struct report_response *rr = (struct report_response *)report->buf;
   out->buf = report->buf + rr->params[6].data.blob.data_offset;
   out->size = rr->params[6].data.blob.data_len;

   return true;
}

// getSignDataFromReport will get the data witch will be signatured
bool getSignDataFromReport(buffer_data *report, buffer_data *out)
{
   if (report->buf == NULL)
   {
      printf("report is null");
      return false;
   }
   struct report_response *rr = (struct report_response *)report->buf;
   out->buf = report->buf;
   out->size = rr->params[5].data.blob.data_offset;

   return true;
}

void dumpDrkCert(buffer_data *certdrk)
{
   for (int i = 0; i < certdrk->size; i++)
      printf("%c", certdrk->buf[i]);
   printf("\n");
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

bool getNOASdata(buffer_data *akcert, buffer_data *signdata, buffer_data *signdrk, buffer_data *certdrk, buffer_data *akpub)
{
   if (akcert->size <= 0)
   {
      printf("akcert is null");
      return false;
   }
   struct ak_cert *ak;
   ak = (struct ak_cert *)akcert->buf;
   uint32_t data_offset;
   uint32_t data_len;
   uint32_t param_count = ak->param_count;
   for (int i = 0; i < param_count; i++)
   {
      // uint32_t param_type = (ak->params[i].tags & 0xf0000000) >> 28;
      // printf("type: %d ",param_type);
      uint32_t param_info = ak->params[i].tags;
      data_offset = ak->params[i].data.blob.data_offset;
      data_len = ak->params[i].data.blob.data_len;
      switch (param_info)
      {
      case RA_TAG_SIGN_TYPE:

         // printf("sign type: %x\n",ak->params[i].data.integer);
         break;
      case RA_TAG_HASH_TYPE:
         // printf("hash type: %x\n",ak->params[i].data.integer);
         break;
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
         // printf("signdata len:%d\n",data_offset);
         break;
      case RA_TAG_CERT_DRK:
         // printf("certdrk len %d\n",certdrk->size);
         restorePEMCert(akcert->buf + data_offset, data_len, certdrk);
         break;

      default:
         break;
      }
   }

   return true;
}

bool tee_verify_signature(buffer_data *report)
{
   // get the report from buffer
   buffer_data akcert;
   bool rt = getAkCertFromReport(report, &akcert);
   if (!rt)
   {
      printf("get AkCert From Report is failed!\n");
      return 0;
   }
   buffer_data signak;
   rt = getAkSignFromReport(report, &signak);
   if (!rt)
   {
      printf("get AkSign From Report is failed!\n");
      return 0;
   }
   buffer_data signdata;
   rt = getSignDataFromReport(report, &signdata);
   if (!rt)
   {
      printf("get Sign Data From Report is failed!\n");
      return 0;
   }
   int scenario = 0;
   rt = verifysig(&signdata, &signak, &akcert, scenario);
   if (!rt)
   {
      printf("verify signature is failed\n");
      return false;
   }
   // TAreport tareport;
   // rt = translateBuf(*report,&tareport);
   // if(rt){
   // 	printf("translate is failed!\n");
   //    return false;
   // }
   // 1. verify the signature by the public key from the cert and digest(is a quoted)

   // char *data = "testdata";
   // char sig[] = "ac90984b642d241161e90b6795c481f1ed0b065dbe713a7f4c562ba99ed91996b2b5fa0bf9319dfead8c98d0e58e10c890b4f628cd8d030b637ff4cf1a12642f4a27aafe794130057b94672c35af27727ad057fc83c8a22e499ab77e3cabe8ee1a0643edc0381e9d837f93ac6de4e0d7657a07e0ad0125ba79ba357a1682d4a7070bd1fe80d900105fdc5b32ec72211cd50e535775e604b880536d94e1e4cfc04710182ca9924decf215071ef50c5af87e178e125a2d5554f0ec07604daf6098dc1dd1b6b69dc813c89fdb2ad5849c125306fd058bf6447bb15251d67ebb4207fb4defde05b2609e029c009ecb18ad5ebbfa67e974057e48376501cc6190ee83";
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
   printf("%s:", printed_name);
   for (int i = 0; i < printed_size; i++)
   {
      printf("%02X", printed[i]);
   }
   printf("\n");
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
      verified = Compare(type, report, baseval); // compare the report with the basevalue

   if (verified == true)
   {
      printf("%s\n", "Verification successful!");
   }
   else
   {
      printf("%s\n", "Verification failed!");
   }

   free(report);
   free(baseval);
   return verified;
}

TA_report *Convert(buffer_data *data)
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

         if (data_offset > data->size || data_offset == 0)
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
            report->signature = (buffer_data*)malloc(sizeof(buffer_data));
            report->signature->buf = (uint8_t *)malloc(sizeof(uint8_t) * data_len);
            report->signature->size = data_len;
            memcpy(report->signature->buf, data->buf + data_offset, data_len);
            // uint32_t cert_offset = data_offset + data_len + sizeof(uint32_t);
            // memcpy(report->cert, data->buf+cert_offset, data_len);
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
//     read_bytes(&(bufuuid.timeHiAndVersion), sizeof(uint16_t), 1, uuid, &offset);
//     read_bytes(&(bufuuid.clockSeqAndNode), sizeof(uint8_t), NODE_LEN, uuid, &offset);
// }

void read_bytes(void *input, size_t size, size_t nmemb, uint8_t *output, size_t *offset)
{
   memcpy(output + *offset, input, size * nmemb);
   *offset += size * nmemb;
}

base_value *LoadBaseValue(const TA_report *report, char *filename)
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
      memcpy(baseval->valueinfo[0], baseval_tmp->valueinfo[0], HASH_SIZE*sizeof(uint8_t));
      memcpy(baseval->valueinfo[1], baseval_tmp->valueinfo[1], HASH_SIZE*sizeof(uint8_t));

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

void str_to_uuid(const char *str, uint8_t *uuid)
{
   //  char substr1[8];
   //  char substr2[4];
   //  char substr3[4];
   //  char substr4[4];
   //  char substr5[12];
   char substr1[9];
   char substr2[5];
   char substr3[5];
   char substr4[5];
   char substr5[13];
   // 8-4-4-4-12
   sscanf(str, "%8[^-]-%4[^-]-%4[^-]-%4[^-]-%12[^-]", substr1, substr2, substr3, substr4, substr5);
   str2hex(substr1, 8, uuid);
   str2hex(substr2, 4, uuid + 4);
   str2hex(substr3, 4, uuid + 4 + 2);
   str2hex(substr4, 4, uuid + 4 + 2 + 2);
   str2hex(substr5, 12, uuid + 4 + 2 + 2 + 2);
}

void uuid_to_str(const uint8_t *uuid, char *str)
{
   // 8-
   hex2str(uuid, 4, str);
   strcpy(str + 4 * 2, "-");
   //  str[4*2] = "-";
   // 8-4-
   hex2str(uuid + 4, 2, str + 9);
   strcpy(str + 9 + 2 * 2, "-");
   //  str[9+2*2] = "-";
   // 8-4-4-
   hex2str(uuid + 4 + 2, 2, str + 14);
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
   str2hex(str, HASH_SIZE * 2, hash);
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

      HighByte += 0x30;     //得到对应的字符，若是字母还需要跳过7个符号
      if (HighByte <= 0x39) //数字
         dest[i * 2] = HighByte;
      else                              //字母
         dest[i * 2] = HighByte + 0x07; //得到字符后保存到对应位置

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
      HighByte = toupper(source[i * 2]); //如果遇到小写，则转为大写处理
      LowByte = toupper(source[i * 2 + 1]);

      if (HighByte <= 0x39) // 0x39对应字符'9',这里表示是数字
         HighByte -= 0x30;

      else //否则为字母，需要跳过7个符号
         HighByte -= 0x37;

      if (LowByte <= 0x39)
         LowByte -= 0x30;

      else
         LowByte -= 0x37;

      /*
       *  假设字符串"3c"
       *  则 HighByte = 0x03,二进制为 0000 0011
       *     LowByte = 0x0c,二进制为 0000 1100
       *
       *      HighByte << 4 = 0011 0000
       *      HighByte | LowByte :
       *
       *      0011 0000
       *      0000 1100
       *    -------------
       *      0011 1100
       *
       *      即 0x3c
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
   fwrite(bvbuf, sizeof(bvbuf), 1, fp_output);
   fclose(fp_output);
}