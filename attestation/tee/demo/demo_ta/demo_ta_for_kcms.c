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

#include <stdlib.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>
#include "tee_trusted_storage_api.h"
#include "tee_time_api.h"
#include "tee_core_api.h"
#include "kcml.h"

#define PARAM_COUNT   4
#define MAX_STR_LEN 64
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3

enum {
    CMD_DATA_ENCRIPT = 0x01,
    CMD_TA_CALLBACK  = 0x02,
    CMD_TA_EXIT      = 0x03,
};

TEE_UUID localUuid = {
    0xbbb2d138, 0xee21, 0x43af, { 0x87, 0x96, 0x40, 0xc2, 0x0d, 0x7b, 0x45, 0xfa }
};
TEE_UUID ktaUuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};
uint32_t new_key_flag = 1;

uint8_t account[MAX_STR_LEN] = "1234";
uint8_t password[MAX_STR_LEN] = "5678";
TEE_UUID masterkey = {
    0x4aeb3aa9, 0x7050, 0x4e40, { 0x97, 0x61, 0x3e, 0x42, 0xf0, 0x3f, 0x2c, 0x63 }
};

typedef struct _StatusFlag {
    TEE_UUID *keyid;
    //A symbol variable which indicates which operetion to be execute after ca call back.
    //0 means no need to reply
    //1 means get key generation reply
    //2 means get key search reply
    //3 means get key delete reply
    uint32_t symbol;
} StatusFlag;

StatusFlag flag = {NULL, 0};
void *keyid_storage_path = "sec_storage_data/takeyid.txt";

void hex2char(uint32_t hex, uint8_t *hexchar, int32_t i) {
    for(i--; i >= 0; i--, hex >>= 4) {
        if ((hex & 0xf) <= 9)
            *(hexchar + i) = (hex & 0xf) + '0';
        else
            *(hexchar + i) = (hex & 0xf) + 'a' - 0x0a;
    }
}

void uuid2char(TEE_UUID uuid, uint8_t charuuid[37]) {
    int32_t i = 0;

    hex2char(uuid.timeLow, charuuid, 8);
    hex2char(uuid.timeMid, charuuid + 9, 4);
    hex2char(uuid.timeHiAndVersion, charuuid + 14, 4);
    for(i = 0; i < 2; i++){
        hex2char(uuid.clockSeqAndNode[i], charuuid + 19 + i * 2, 2);
    }
    for(i = 0; i < 6; i++){
        hex2char(uuid.clockSeqAndNode[i+2], charuuid + 24 + i * 2, 2);
    }
    charuuid[8] = '-';
    charuuid[13] = '-';
    charuuid[18] = '-';
    charuuid[23] = '-';
    charuuid[36] = '\0';
}

void char2uuid(TEE_UUID *uuid, int8_t charuuid[37]) {
    int32_t i = 0;
    char *stop;
    // int8_t buffer[3];
    uuid->timeLow = strtoul((char*)charuuid, &stop, 16);
    uuid->timeMid = strtoul(stop + 1, &stop, 16);
    uuid->timeHiAndVersion = strtoul(stop + 1, &stop, 16);
    for(i = 0; i < 2; i++) {
        uuid->clockSeqAndNode[i] = strtoul((char*)charuuid + 19 + i * 2, &stop, 16) >> (8 - i * 8);
    }
    /*
    for(i = 0; i < 6; i++) {
        buffer[0] = *(charuuid + 24 + i * 2);
        buffer[1] = *(charuuid + 25 + i * 2);
        uuid->clockSeqAndNode[i + 2] = strtoul((char*)buffer, &stop, 16);
    }
    */
   for(i = 0; i < 6; i++) {
        uuid->clockSeqAndNode[i+2] = strtoul((char*)charuuid + 24 + i * 2, &stop, 16) >> (40 - i * 8);
    }
}

//The encryption operation or other operations needs key
TEE_Result encrypt(uint8_t *keyvalue) {
    char *data = "demo data";
    (void)keyvalue;
    (void)data;
    return TEE_SUCCESS;
}

TEE_Result delete_key_opt(TEE_UUID *keyid, TEE_Param params[PARAM_COUNT] ) {
    TEE_Result ret;
    ret = delete_key(&localUuid, account, password, keyid);
    if (ret != TEE_SUCCESS) {
        tloge("delete key failed");
        return ret;
    }
    params[3].value.a = 1;
    flag.symbol = 3;
    return TEE_SUCCESS;
}

//
TEE_Result encrypt_data_pre(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    uint8_t *keyvalue = NULL;
    //A flag indicating whether a new key is required
    TEE_UUID keyid = {0};
    TEE_ObjectHandle keyid_data = NULL;
    uint32_t len = 36, count = 0;
    int8_t *keyidchar = NULL;

    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("prepare to encrypt data");
    uint32_t twice_search_flag = 0;

    if(new_key_flag == 1) {
        ret = generate_key(&localUuid, account, password, &masterkey);
        if(ret != TEE_SUCCESS) {
            tloge("generate key command failed");
            return ret;
        }
        params[PARAMETER_FOURTH].value.a = 1;
        flag.symbol = 1;
        new_key_flag -= 1;
        tlogd("prepare to encrypt data success");
        return TEE_SUCCESS;
    }
    if(new_key_flag == 0) {
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, keyid_storage_path, strlen(keyid_storage_path),
                TEE_DATA_FLAG_ACCESS_READ, &keyid_data);
        if (ret != TEE_SUCCESS) {
            tloge("failed to open file:ret = 0x%x\n", ret);
            return ret;
        }
        keyidchar = TEE_Malloc(len + 1, 0);
        if (keyidchar == NULL) {
            tloge("failed to open file:ret = 0x%x\n", ret);
            TEE_CloseObject(keyid_data);
            return ret;
        }
        ret = TEE_ReadObjectData(keyid_data, keyidchar, len, &count);
        if (ret != TEE_SUCCESS) {
            TEE_CloseObject(keyid_data);
            TEE_Free(keyidchar);
        return ret;
        }
        TEE_CloseObject(keyid_data);
        tlogd("%s",keyidchar);
        char2uuid(&keyid, keyidchar);
        keyvalue = TEE_Malloc(KEY_SIZE, 0);
        ret = search_key(&localUuid, account, password, &keyid, &masterkey, keyvalue, &twice_search_flag);
        if(ret != TEE_SUCCESS) {
            tloge("search command failed");
            return ret;
        }
        if(twice_search_flag) {
            params[PARAMETER_FOURTH].value.a = 1;
            flag.keyid = &keyid;
            flag.symbol = 2;
            tlogd("prepare to encrypt data success");
            return TEE_SUCCESS;
        }
        encrypt(keyvalue);
        TEE_Free(keyvalue);
        tlogd("encrypt data success");
        ret = delete_key_opt(&keyid, params);
        if (ret != TEE_SUCCESS) {
            tloge("generate delete cmd fail");
            return ret;
        }
    }
    return TEE_SUCCESS;
}

TEE_Result call_back(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    TEE_UUID keyid = {0};
    char keyidchar[37] = {0};
    int8_t *keyiddelete = NULL;
    uint8_t *keyvalue = NULL;
    TEE_ObjectHandle keyid_data = NULL;
    uint32_t len = 36, count = 0;

    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("start to encrypt data");
    uint32_t twice_search_flag;
    switch(flag.symbol) {
    case 1:
        ret = get_kcm_reply(&localUuid, account, password, &keyid, keyvalue);
        if (ret != TEE_SUCCESS) {
            tloge("get generate key reply failed");
            return ret;
        }
        uuid2char(keyid, (uint8_t*)keyidchar);
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, keyid_storage_path, strlen(keyid_storage_path),
                TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, NULL, 0, &keyid_data);
        if (ret != TEE_SUCCESS) {
            tloge("Failed to create file: ret = 0x%x\n", ret);
            return ret;
        }

        ret = TEE_WriteObjectData(keyid_data, keyidchar, strlen((char*)keyidchar));
        if (ret != TEE_SUCCESS) {
            tloge("Failed to write file: ret = 0x%x\n", ret);
            TEE_CloseObject(keyid_data);
            return ret;
        }
        params[3].value.a = 0;
        TEE_CloseObject(keyid_data);
        break;
    case 2:
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, keyid_storage_path, strlen(keyid_storage_path),
                TEE_DATA_FLAG_ACCESS_READ, &keyid_data);
        if (ret != TEE_SUCCESS) {
            tloge("failed to open file:ret = 0x%x\n", ret);
            return ret;
        }
        ret = TEE_ReadObjectData(keyid_data, keyidchar, len, &count);
        if (ret != TEE_SUCCESS) {
            TEE_CloseObject(keyid_data);
            TEE_Free(keyidchar);
        return ret;
        }
        TEE_CloseObject(keyid_data);
        char2uuid(&keyid, (int8_t*)keyidchar);
        ret = search_key(&localUuid, account, password, &keyid, &masterkey, keyvalue, &twice_search_flag);
        if (ret != TEE_SUCCESS) {
            tloge("get generate key reply failed");
            return ret;
        }
        if(twice_search_flag) {
            tloge("not find designated key");
            return TEE_ERROR_TIMEOUT;
        }
        params[3].value.a = 0;
        break;
    case 3:
        
        ret = get_kcm_reply(&localUuid, account, password, &keyid, NULL);
        if (ret != TEE_SUCCESS) {
            params[3].value.a = 2;
            tloge("delete key failed");
            return ret;
        } else {
            params[3].value.a = 0;
            tlogd("delete key success");
            return TEE_SUCCESS;
        }
    default:
        tloge("parameter symbol is wrong");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    encrypt(keyvalue);
    tlogd("encrypt data success");

    //a delete key attribute example
    if(flag.symbol == 2) {
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, keyid_storage_path, strlen(keyid_storage_path),
                TEE_DATA_FLAG_ACCESS_READ, &keyid_data);
        if (ret != TEE_SUCCESS) {
            tloge("failed to open file:ret = 0x%x\n", ret);
            return ret;
        }
        keyiddelete = TEE_Malloc(len + 1, 0);
        if (keyiddelete == NULL) {
            tloge("failed to open file:ret = 0x%x\n", ret);
            TEE_CloseObject(keyid_data);
            return ret;
        }
        ret = TEE_ReadObjectData(keyid_data, keyiddelete, len, &count);
        if (ret != TEE_SUCCESS) {
            TEE_CloseObject(keyid_data);
            TEE_Free(keyiddelete);
        return ret;
        }
        char2uuid(&keyid, keyiddelete);
        ret = delete_key_opt(&keyid, params);
        if (ret != TEE_SUCCESS) {
            tloge("generate delete cmd fail");
            return ret;
        }
    }
    tlogd("execute call back success");
    return TEE_SUCCESS;
}

TEE_Result ta_exit() {
    TEE_Result ret;
    TEE_ObjectHandle keyid_data = NULL;

    ret = clear_cache(&localUuid, account, password);
    if(ret != TEE_SUCCESS) {
        tloge("clear cache failed");
        return ret;
    }
    ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, keyid_storage_path, strlen(keyid_storage_path),
            TEE_DATA_FLAG_ACCESS_WRITE_META, &keyid_data);
    if (ret != TEE_SUCCESS) {
        tloge("failed to open file:ret = 0x%x\n", ret);
        return ret;
    }
    TEE_CloseAndDeletePersistentObject(keyid_data);
    tlogd("ta exit preparation success");
    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;
    ret = addcaller_ca_exec("/root/vendor/bin/demo_ca", "root");
    if (ret != TEE_SUCCESS) {
        tloge("add caller ca failed");
        return TEE_ERROR_GENERIC;
    }
    tlogd("add caller ca success");
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parm_type,
    TEE_Param params[PARAM_COUNT], void** session_context)
{
    (void)parm_type;
    (void)params;
    (void)session_context;
    tlogd("open session success");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void* session_context, uint32_t cmd,
    uint32_t param_type, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    (void)session_context;

    tlogd("---- TA invoke command ----------- ");
    switch (cmd) {
    case CMD_DATA_ENCRIPT:
        ret = encrypt_data_pre(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("encrypt data process failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_TA_CALLBACK:
        ret = call_back(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("execute call back operation failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_TA_EXIT:
        ret = ta_exit();
        if(ret != TEE_SUCCESS) {
            tloge("execute call back operation failed0x%x", ret);
            return ret;
        }
        break;
    default:
        tloge("Unknown cmd is %u", cmd);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
    return  ret;
}

void TA_CloseSessionEntryPoint(void* session_context){
    (void)session_context;
    tlogd("---- close session ----- ");
}

void TA_DestroyEntryPoint(void){
    tlogd("---- destory TA ---- ");
}
