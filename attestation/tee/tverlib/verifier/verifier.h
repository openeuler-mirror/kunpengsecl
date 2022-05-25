#ifndef __VERIFIER_LIB__
#define __VERIFIER_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <assert.h>
//QCAlib
#define KEY_TAG_TYPE_MOVE_BITS 28
#define RA_INTEGER (1 << KEY_TAG_TYPE_MOVE_BITS)
#define RA_BYTES   (2 << KEY_TAG_TYPE_MOVE_BITS)
//scenario number
#define RA_SCENARIO_NO_AS        0
#define RA_SCENARIO_AS_NO_DAA    1
//Attester will send the report by this type
typedef struct
{
    uint32_t size;
    uint8_t *buf;
    
} buffer_data;

typedef struct {
	char	version[5]; 
	char	timestamp[9]; //时间戳，记录系统时间，用户防重放以及时间校验
	char	nonce[33];
	char 	uuid[65];
	char	alg[3];  //指定hash算法与签名算法类型，默认0为 SHA256 RSA4096
	char	image_hash[33];
	char	hash[33];
	char	reserve[33];
	char	signature[513];
	char 	cert[513];//AK cert
}TAreport;

typedef struct{
   char uuid[65];
   char valueinfo[2][33];     //valueinfo[0]=img measurement and valueinfo[1]=mem measurement
}BaseValue;

#define USER_DATA_SIZE 64

struct ra_data_offset {
    uint32_t data_len;  //data_len表示实际数据的长度
    uint32_t data_offset; //指从整个report缓冲区起始地址的偏移大小
};

struct ra_params {
    uint32_t tags;
    union {
        uint32_t integer;
        struct ra_data_offset blob;
    } data;
} __attribute__((__packed__));

struct ra_params_set_t {
    uint32_t param_count;
    struct ra_params params[0];
} __attribute__((__packed__));
enum ra_alg_types {
    RA_ALG_RSA_3072     = 0x20000,
    RA_ALG_RSA_4096     = 0x20001,  // PSS padding
    RA_ALG_SHA_256      = 0x20002,
    RA_ALG_SHA_384      = 0x20003,
    RA_ALG_SHA_512      = 0x20004,
    RA_ALG_ECDSA        = 0x20005,
    RA_ALG_ED25519      = 0x20006,
    RA_ALG_SM2_DSA_SM3  = 0x20007,
    RA_ALG_SM3          = 0x20008,
};
enum ra_tags {
    /*整数类型*/
    RA_TAG_SIGN_TYPE     = RA_INTEGER | 0,
    RA_TAG_HASH_TYPE     = RA_INTEGER | 1,
    /*字节流类型*/
    RA_TAG_QTA_IMG_HASH  = RA_BYTES   | 0,
    RA_TAG_TA_IMG_HASH   = RA_BYTES   | 1,
    RA_TAG_QTA_MEM_HASH  = RA_BYTES   | 2,
    RA_TAG_TA_MEM_HASH   = RA_BYTES   | 3,
    RA_TAG_RESERVED      = RA_BYTES   | 4,
    RA_TAG_AK_PUB        = RA_BYTES   | 5,
    RA_TAG_SIGN_DRK      = RA_BYTES   | 6,
    RA_TAG_SIGN_AK       = RA_BYTES   | 7,
    RA_TAG_CERT_DRK      = RA_BYTES   | 8,
    RA_TAG_CERT_AK       = RA_BYTES   | 9,
};
#define NODE_LEN 8
typedef struct tee_uuid {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[NODE_LEN];
} TEE_UUID;

struct __attribute__((__packed__)) report_response {
    uint32_t version;
    uint64_t ts;
    uint8_t nonce[USER_DATA_SIZE];
    TEE_UUID uuid;
    uint32_t scenario;
    uint32_t param_count;
    struct ra_params params[0];
    /* following buffer data:
     * (1)ta_img_hash []
     * (2)ta_mem_hash []
     * (3)reserverd []
     * (4)sign_ak []
     * (5)ak_cert []
     */
};
#define KEY_PURPOSE_SIZE 32 //test
struct ak_cert {
uint32_t version;
uint64_t ts;
char purpose[KEY_PURPOSE_SIZE];
uint32_t param_count;
struct ra_params params[0];
/* following buffer data:
* (1)qta_img_hash []
 * (2)qta_mem_hash []
 * (3)reserverd []
 * (4)ak_pub []
* (5)sign_drk []
* (6)cert_drk []
*/
} __attribute__ ((__packed__));
const int len[]={4,8,32,64,2,32,32,32,512,512};

bool tee_verify_signature(buffer_data *report);

bool tee_verify(buffer_data *data,int type,char *filename);

#endif