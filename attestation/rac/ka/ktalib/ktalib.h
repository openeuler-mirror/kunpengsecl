#ifndef __KTA_LIB__
#define __KTA_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
//#include "tee_client_api.h"
#include "../teesimulator/tee.h"
//#include "securec.h"
/*
    主要思路：
        1.初始化KTA的过程每次只调用一次initialize函数
        2.初始化KTA后建立的会话不会立即断开
        3.通过不断调用InvokeCommand函数进行operation的返回
*/
//用来指定go与c之间的缓冲区大小

struct buffer_data{
    uint32_t size;
    uint8_t *buf;
};
#define RSA_PUBLIC_SZIE  4096
#define LIBKTA_PREFIX "libkta"
#define TAG_ERROR "[error]"
#define tloge(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBKTA_PREFIX, TAG_ERROR, __LINE__, ##args)

TEEC_Result RemoteAttestInitial(uint32_t cmdnum,struct buffer_data *req,struct buffer_data*rsp);

TEEC_Result RemoteAttestKTA(uint32_t cmdnum,struct buffer_data *req,struct buffer_data *rsp);

TEEC_Result InitContextSession(TEEC_Context *context, TEEC_Session *session);
TEEC_Result KTAinitialize(TEEC_Session *session, struct buffer_data* kcmPubKey, struct buffer_data* kcmPrivKey,struct buffer_data* ktaPubCert, struct buffer_data *out_data);
TEEC_Result KTAgetCommand(TEEC_Session *session, struct buffer_data* out_data);
TEEC_Result KTAsendCommandreply(TEEC_Session *session, struct buffer_data* in_data);
void KTAshutdown(TEEC_Context *context, TEEC_Session *session);

#endif