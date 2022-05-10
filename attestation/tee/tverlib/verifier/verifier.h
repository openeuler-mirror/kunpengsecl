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

const int len[]={4,8,32,64,2,32,32,32,512,512};

bool VerifySignature(buffer_data *report);

bool VerifyManifest(buffer_data *data,int type,char *filename);

#endif