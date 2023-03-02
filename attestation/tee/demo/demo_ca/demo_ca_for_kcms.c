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

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include "tee_client_api.h"

#define OPERATION_START_FLAG 1
#define MAX_STR_LEN 64
#define HASH_SIZE 65
#define MEMHASH_PARAM 0
#define IMGHASH_PARAM 0
#define SYMBOL_PARAM 3
#define VALUE_INIT 0x7fffffff

static const TEEC_UUID Uuid = {
    0xbbb2d138, 0xee21, 0x43af, { 0x87, 0x96, 0x40, 0xc2, 0x0d, 0x7b, 0x45, 0xfa }
};
static const char *hash_file = "/root/vendor/bin/hash_bbb2d138-ee21-43af-8796-40c20d7b45fa.txt";

enum {
    CMD_DATA_ENCRIPT = 0x01, //a scene which needs ta to encrypt some data
    CMD_TA_CALLBACK  = 0x02, //a scene which ta needs to be call back
    CMD_TA_EXIT      = 0x03, //a scene which ta exits and needs to clear its info in kta
};

//read two hash values from hash file
bool readfile(char *ta_mem, char *ta_img) {
    FILE *f;
    char *mem_name = NULL;
    char *img_name = NULL;
    char punc;
    if((f = fopen(hash_file, "r")) == NULL) {
        TEEC_Error("read hash file failed!\n");
        return 1;
    }
    fscanf(f,"%s%c%s", mem_name, punc, ta_mem);
    if((strcmp(mem_name, "mem_hash") != 0) || strlen(ta_mem) != 64) {
        TEEC_Error("read mem_hash from hash file failed!\n");
        return 1;
    }

    fscanf(f,"%s%c%s", img_name, punc, ta_img);
    if((strcmp(img_name, "img_hash") != 0) || strlen(ta_img) != 64) {
        TEEC_Error("read img_hash from hash file failed!\n");
        return 1;
    }
    return 0;
}

int main(){
    TEEC_Context context = {0};
    TEEC_Session session = {0};
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result result;
    int32_t i = 0;
    char mem_hash[HASH_SIZE];
    char img_hash[HASH_SIZE];
    bool symbol = 1;

    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        printf("initial context failed\n");
        goto end1;
    }

    context.ta_path = (uint8_t*)"/root/data/bbb2d138-ee21-43af-8796-40c20d7b45fa.sec";
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    result = TEEC_OpenSession(&context, &session, &Uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("open session failed\n");
        goto end2;
    }
    symbol = readfile(mem_hash, img_hash);
    if(symbol == 1) {
        goto end3;
    }

    //Demonstrate twice, first for key generation, second for key search
    for(; i < 2; i++) {
        operation.started = OPERATION_START_FLAG;
        operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_NONE,
            TEEC_VALUE_OUTPUT //we need one parameter to identify whether needs ca to call back
            );
        operation.params[MEMHASH_PARAM].tmpref.buffer = mem_hash;
        operation.params[MEMHASH_PARAM].tmpref.size = HASH_SIZE;
        operation.params[IMGHASH_PARAM].tmpref.buffer = img_hash;
        operation.params[IMGHASH_PARAM].tmpref.size = HASH_SIZE;
        operation.params[SYMBOL_PARAM].value.a = VALUE_INIT; //a marks whether ta needs needs to be called back, a=0 means not need
        result = TEEC_InvokeCommand(&session, CMD_DATA_ENCRIPT, &operation, &origin);
        if(result != TEEC_SUCCESS) {
            printf("encrypt data process failed, codes=0x%x, origin=0x%x\n", result, origin);
            goto end3;
        }
        if(operation.params[SYMBOL_PARAM].value.a == 0) {
            printf("encrypt data process succeeded\n");
            goto else_options;
        } else if (operation.params[SYMBOL_PARAM].value.a != 1) {
            printf("encrypt data process failed, parameter is wrong\n");
            goto end3;
        } else {
            printf("ta needs to be called back, wait 3s\n");
            sleep(3);
            operation.started = OPERATION_START_FLAG;
            operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_MEMREF_TEMP_INPUT,
                TEEC_NONE,
                TEEC_VALUE_OUTPUT //we need one parameter to identify whether needs ca to call back
            );
            operation.params[MEMHASH_PARAM].tmpref.buffer = mem_hash;
            operation.params[MEMHASH_PARAM].tmpref.size = HASH_SIZE;
            operation.params[IMGHASH_PARAM].tmpref.buffer = img_hash;
            operation.params[IMGHASH_PARAM].tmpref.size = HASH_SIZE;
            operation.params[SYMBOL_PARAM].value.a = VALUE_INIT; //a marks whether ta needs needs to be called back, a=0 means not need
            result = TEEC_InvokeCommand(&session, CMD_TA_CALLBACK, &operation, &origin);
            if(result != TEEC_SUCCESS) {
                printf("ta call back failed, codes=0x%x, origin=0x%x\n", result, origin);
                goto end3;
            }
            if(operation.params[SYMBOL_PARAM].value.a == 0) {
                printf("encrypt data process succeeded\n");
                continue;
            } else if (operation.params[SYMBOL_PARAM].value.a != 1) {
                printf("encrypt data process failed, parameter is wrong\n");
                goto end3;
            } else {
                printf("ta needs to be called back, wait 3s\n");
                sleep(3);
                operation.started = OPERATION_START_FLAG;
                operation.paramTypes = TEEC_PARAM_TYPES(
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_MEMREF_TEMP_INPUT,
                    TEEC_NONE,
                    TEEC_VALUE_OUTPUT //we need one parameter to identify whether needs ca to call back
                );
                operation.params[MEMHASH_PARAM].tmpref.buffer = mem_hash;
                operation.params[MEMHASH_PARAM].tmpref.size = HASH_SIZE;
                operation.params[IMGHASH_PARAM].tmpref.buffer = img_hash;
                operation.params[IMGHASH_PARAM].tmpref.size = HASH_SIZE;
                operation.params[SYMBOL_PARAM].value.a = VALUE_INIT; //a marks whether ta needs needs to be called back, a=0 means not need
                result = TEEC_InvokeCommand(&session, CMD_TA_CALLBACK, &operation, &origin);
                if(result != TEEC_SUCCESS) {
                    printf("ta call back failed, codes=0x%x, origin=0x%x\n", result, origin);
                    goto end3;
                }
                if(operation.params[SYMBOL_PARAM].value.a == 0) {
                    printf("encrypt data process succeeded\n");
                    goto else_options;
                } else printf("encrypt data process failed\n");
            }
        }
    }

//other options to be executed, here use ta exit as an example
else_options:
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_NONE,
        TEEC_NONE
    );
    operation.params[MEMHASH_PARAM].tmpref.buffer = mem_hash;
    operation.params[MEMHASH_PARAM].tmpref.size = HASH_SIZE;
    operation.params[IMGHASH_PARAM].tmpref.buffer = img_hash;
    operation.params[IMGHASH_PARAM].tmpref.size = HASH_SIZE;
    result = TEEC_InvokeCommand(&session, CMD_TA_EXIT, &operation, &origin);
    if(result != TEEC_SUCCESS) {
        printf("ta exit failed, codes=0x%x, origin=0x%x\n", result, origin);
        goto end3;
    }
    printf("ta exit succeeded\n");

end3:
    TEEC_CloseSession(&session);
end2:
    TEEC_FinalizeContext(&context);
end1:
    return 0;
}