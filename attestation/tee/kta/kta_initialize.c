/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: leezhenxiang
Create: 2022-11-04
Description: initialize module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
    2. 2022-11-18   waterh2o
        redefine some interface
    3. 2022-11-25   waterh2o
        Function implementation
*/

#include <kta_common.h>
#include <tee_mem_mgmt_api.h>
#include <tee_trusted_storage_api.h>
#include <tee_crypto_api.h>
#include <tee_crypto_api.h>
#include <string.h>
#include <ctype.h>
#include <securec.h>
#include <cJSON.h>

extern Cache cache;
extern CmdQueue cmdqueue;
extern ReplyCache replycache;

TEE_UUID taUuid = {
    0xbbb2d138, 0xee21, 0x43af, { 0x87, 0x96, 0x40, 0xc2, 0x0d, 0x7b, 0x45, 0xfa }
};

void str2hex(const uint8_t *source, int source_len, char *dest) {
    for (int32_t i = 0; i < source_len; i++) {
        if ((source[i] >> 4) <= 9) // 0x39 corresponds to the character '9'
            dest[2 * i] = (source[i] >> 4) + 0x30;
        else // Otherwise, it is a letter, and 7 symbols need to be skipped
            dest[2 * i] = (source[i] >> 4) + 0x37;
        if ((source[i] % 16) <=9)
            dest[2 * i + 1] = (source[i] % 16) + 0x30;
        else
            dest[2 * i + 1] = (source[i] % 16) + 0x37;
    }
}

void hex2str(const char *source, int dest_len, uint8_t *dest) {
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

TEE_Result saveKeyandCert(char *name, uint8_t *value, size_t size) {
    uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
    uint32_t w_flags = TEE_DATA_FLAG_ACCESS_WRITE;
    void *create_objectID = name;
    TEE_ObjectHandle persistent_data = NULL;
    TEE_Result ret;
    char *write_buffer = TEE_Malloc((2*size+1)*sizeof(char), 0);
    str2hex(value, size, write_buffer);
    ret = TEE_CreatePersistentObject(storageID, create_objectID, strlen(create_objectID), w_flags, TEE_HANDLE_NULL, NULL, 0, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to create file: ret = 0x%x\n", ret);
        TEE_Free(write_buffer);
        return ret;
    }

    ret = TEE_WriteObjectData(persistent_data, write_buffer, strlen(write_buffer));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to write file: ret = 0x%x\n", ret);
        TEE_CloseObject(persistent_data);
        TEE_Free(write_buffer);
        return ret;
    }
    TEE_CloseObject(persistent_data);
    TEE_Free(write_buffer);
    return TEE_SUCCESS;
}

TEE_Result saveKTAPriv(char *name, ktaprivkey *value) {
    uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
    uint32_t w_flags = TEE_DATA_FLAG_ACCESS_WRITE;
    void *create_objectID = name;
    TEE_ObjectHandle persistent_data = NULL;
    TEE_Result ret;
    cJSON *kta_priv_json = cJSON_CreateObject();
    char *kta_priv = NULL;
    char modulus_buffer[2*RSA_PUB_SIZE+1] = {0};
    char exponent_buffer[2*RSA_PUB_SIZE+1] = {0};
    str2hex(value->modulus, RSA_PUB_SIZE, modulus_buffer);
    str2hex(value->privateExponent, RSA_PUB_SIZE, exponent_buffer);
    cJSON_AddStringToObject(kta_priv_json, "modulus", modulus_buffer);
    cJSON_AddStringToObject(kta_priv_json, "privateExponent", exponent_buffer);
    kta_priv = cJSON_PrintUnformatted(kta_priv_json);
    ret = TEE_CreatePersistentObject(storageID, create_objectID, strlen(create_objectID), w_flags, TEE_HANDLE_NULL, NULL, 0, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to create file: ret = 0x%x\n", ret);
        return ret;
    }
    ret = TEE_WriteObjectData(persistent_data, kta_priv, strlen(kta_priv));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to write file: ret = 0x%x\n", ret);
        TEE_CloseObject(persistent_data);
        return ret;
    }
    TEE_CloseObject(persistent_data);
    cJSON_free(kta_priv);
    cJSON_Delete(kta_priv_json);
    return TEE_SUCCESS;
}

TEE_Result restoreKeyandCert(char *name, uint8_t *buffer, size_t buf_len) {
    TEE_Result ret;
    uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
    uint32_t r_flags = TEE_DATA_FLAG_ACCESS_READ;
    void *create_objectID = name;
    TEE_ObjectHandle persistent_data = NULL;
    uint32_t pos = 0;
    uint32_t len = 0;
    char *read_buffer = NULL;
    uint32_t count = 0;
    ret = TEE_OpenPersistentObject(storageID, create_objectID, strlen(create_objectID),r_flags, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to open file:ret = 0x%x\n", ret);
        return ret;
    }

    ret = TEE_InfoObjectData(persistent_data, &pos, &len);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to open file:ret = 0x%x\n", ret);
        TEE_CloseObject(persistent_data);
        return ret;
    }

    read_buffer = TEE_Malloc(len + 1, 0);
    if (read_buffer == NULL) {
        tloge("Failed to open file:malloc fail, len=%d\n", len + 1);
        TEE_CloseObject(persistent_data);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* 读取已存入的数据 */
    ret = TEE_ReadObjectData(persistent_data, read_buffer, len, &count);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        return ret;
    }
    uint8_t *read_data = TEE_Malloc(len/2, 0);
    if (read_data == NULL) {
        tloge("Failed to open file:malloc fail, len=%d\n", len/2);
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    hex2str(read_buffer, len/2, read_data);
    int32_t rc = memmove_s(buffer, buf_len, read_data, len/2);
    if (rc != 0) {
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        TEE_Free(read_data);
        return TEE_ERROR_SECURITY;
    }
    TEE_CloseObject(persistent_data);
    TEE_Free(read_buffer);
    TEE_Free(read_data);
    return TEE_SUCCESS;
}

TEE_Result restoreKTAPriv(char *name, uint8_t modulus[RSA_PUB_SIZE], uint8_t privateExponent[RSA_PUB_SIZE]) {
    TEE_Result ret;
    uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
    uint32_t r_flags = TEE_DATA_FLAG_ACCESS_READ;
    void *create_objectID = name;
    TEE_ObjectHandle persistent_data = NULL;
    uint32_t pos = 0;
    uint32_t len = 0;
    char *read_buffer = NULL;
    uint32_t count = 0;
    uint8_t strmodulus[RSA_PUB_SIZE] = {0};
    uint8_t strexponent[RSA_PUB_SIZE] = {0};
    ret = TEE_OpenPersistentObject(storageID, create_objectID, strlen(create_objectID),r_flags, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to open file:ret = 0x%x\n", ret);
        return ret;
    }

    ret = TEE_InfoObjectData(persistent_data, &pos, &len);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to open file:ret = 0x%x\n", ret);
        TEE_CloseObject(persistent_data);
        return ret;
    }

    read_buffer = TEE_Malloc(len + 1, 0);
    if (read_buffer == NULL) {
        tloge("Failed to open file:malloc fail, len=%d\n", len+1);
        TEE_CloseObject(persistent_data);
        return ret;
    }

    /* 读取已存入的数据 */
    ret = TEE_ReadObjectData(persistent_data, read_buffer, len, &count);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        return ret;
    }
    cJSON *kta_priv_json = cJSON_Parse(read_buffer);
    cJSON *jsonmodulus = cJSON_GetObjectItemCaseSensitive(kta_priv_json, "modulus");
    cJSON *jsonprivateExponent = cJSON_GetObjectItemCaseSensitive(kta_priv_json, "privateExponent");
    hex2str(jsonmodulus->valuestring, strlen(jsonmodulus->valuestring)/2, strmodulus);
    hex2str(jsonprivateExponent->valuestring, strlen(jsonprivateExponent->valuestring)/2, strexponent);
    int rc = memcpy_s(modulus, RSA_PUB_SIZE, strmodulus, RSA_PUB_SIZE);
    if (rc != 0) {
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        cJSON_Delete(kta_priv_json);
        return TEE_ERROR_SECURITY;
    }
    rc = memcpy_s(privateExponent, RSA_PUB_SIZE, strexponent, RSA_PUB_SIZE);
    if (rc != 0) {
        TEE_CloseObject(persistent_data);
        TEE_Free(read_buffer);
        cJSON_Delete(kta_priv_json);
        return TEE_ERROR_SECURITY;
    }
    char strmodulus1[201] = {0};
    char strmodulus2[201] = {0};
    char strmodulus3[113] = {0};
    memcpy_s(strmodulus1,201,jsonmodulus->valuestring,200);
    memcpy_s(strmodulus2,201,jsonmodulus->valuestring+200,200);
    memcpy_s(strmodulus3,113,jsonmodulus->valuestring+400,112);
    tlogd("strmodulus1: %s", strmodulus1);
    tlogd("strmodulus2: %s", strmodulus2);
    tlogd("strmodulus3: %s", strmodulus3);
    char strprivateExponent1[201] = {0};
    char strprivateExponent2[201] = {0};
    char strprivateExponent3[113] = {0};
    memcpy_s(strprivateExponent1,201,jsonprivateExponent->valuestring,200);
    memcpy_s(strprivateExponent2,201,jsonprivateExponent->valuestring+200,200);
    memcpy_s(strprivateExponent3,113,jsonprivateExponent->valuestring+400,112);
    tlogd("strprivateExponent1: %s", strprivateExponent1);
    tlogd("strprivateExponent2: %s", strprivateExponent2);
    tlogd("strprivateExponent3: %s", strprivateExponent3);
    TEE_CloseObject(persistent_data);
    TEE_Free(read_buffer);
    cJSON_Delete(kta_priv_json);
    tlogd("success!!");
    return TEE_SUCCESS;
}

TEE_Result initStructure(){
    //init cache
    cache.head = -1;
    cache.tail = -1;
    for(int i=0;i<MAX_TA_NUM;i++){
        cache.ta[i].next = -1;
        cache.ta[i].head = -1;
        cache.ta[i].tail = -1;
        for(int j=0;j<MAX_KEY_NUM;j++){
            cache.ta[i].key[j].next = -1;
        }
    }
    cache.head = 0;
    cache.tail = 0;
    memcpy_s(cache.ta[cache.head].account, 64, "1234", 5);
    memcpy_s(cache.ta[cache.head].password, 64, "5678", 5);
    cache.ta[cache.head].id = taUuid;
    cache.ta[cache.head].next = -1;

    //init cmdqueue
    cmdqueue.head = 0;
    cmdqueue.tail = 0;
    //init replycache
    replycache.head = -1;
    replycache.tail = -1;
    for(int i=0;i<MAX_QUEUE_SIZE;i++){
        replycache.list[i].next = -1;
    }
    return TEE_SUCCESS;
}

TEE_Result reset(char *name){
    TEE_Result ret;
    uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
    uint32_t r_flags = TEE_DATA_FLAG_ACCESS_READ;
    TEE_ObjectHandle persistent_data = NULL;
    ret = TEE_OpenPersistentObject(storageID, name, strlen(name),
    r_flags | TEE_DATA_FLAG_ACCESS_WRITE_META, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to execute TEE_OpenPersistentObject:ret = %x\n", ret);
        return ret;
    }
    TEE_CloseAndDeletePersistentObject(persistent_data);
    return TEE_SUCCESS;
}

TEE_Result Reset_All(){
    TEE_Result ret;
    ret = reset("sec_storage_data/ktacert.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset ktacert\n", ret);
        return ret;
    }
    ret = reset("sec_storage_data/kcmpub.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset kcmpub\n", ret);
        return ret;
    }
    ret = reset("sec_storage_data/ktakey.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset ktakey\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}
