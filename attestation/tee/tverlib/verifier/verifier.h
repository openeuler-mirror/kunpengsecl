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

const int len[]={4,8,32,64,2,32,32,32,512,512};

bool VerifySignature(buffer_data *report);

bool VerifyManifest(buffer_data *data,int type,char *filename);

#endif