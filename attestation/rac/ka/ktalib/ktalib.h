#ifndef __KTA_LIB__
#define __KTA_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "tee_client_api.h"
// #include "../teesimulator/tee.h"
//#include "securec.h"
/*
    主要思路：
        1.初始化KTA的过程每次只调用一次initialize函数
        2.初始化KTA后建立的会话不会立即断开
        3.通过不断调用InvokeCommand函数进行operation的返回
*/

#define LIBKTA_PREFIX "libkta"
#define TAG_ERROR "[error]"
#define tloge(fmt, args...) printf("[%s] %s %d:" fmt " ", LIBKTA_PREFIX, TAG_ERROR, __LINE__, ##args)

//用来指定go与c之间的缓冲区大小
struct buffer_data{
    uint32_t size;
    uint8_t *buf;
};

TEEC_Result InitContextSession(uint8_t* ktapath);

TEEC_Result KTAinitialize(struct buffer_data* kcmPubKey_N, struct buffer_data* ktaPubCert, struct buffer_data* ktaPrivKey_N, struct buffer_data* ktaPrivKey_D, struct buffer_data *out_data);

TEEC_Result KTAgetCommand(struct buffer_data* out_data, uint32_t* retnum);

TEEC_Result KTAsendCommandreply(struct buffer_data* in_data);

void KTAshutdown();

TEEC_Result KTAterminate();

#endif