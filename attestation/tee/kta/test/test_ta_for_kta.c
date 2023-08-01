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

#include <securec.h>
#include <stdlib.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include "tee_trusted_storage_api.h"
#include "tee_time_api.h"
#include "tee_core_api.h"
#include <tee_defines.h>
#include <tee_mem_mgmt_api.h>
#include <unistd.h>
#include "kta_test.h"

#define PARAM_COUNT   4
#define MAX_STR_LEN 64
#define HASH_SIZE 65
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3
#define KEY_SIZE 4096

enum {
    CMD_GENERATE            = 0x01, //a scene which needs ta to encrypt some data
    CMD_GENERATE_CALLBACK   = 0x02, //a scene which ta needs to be call back
    CMD_TA_EXIT             = 0x03, //a scene which ta exits and needs to clear its info in kta
    CMD_SEARCH              = 0x04,
    CMD_DELETE_CALLBACK     = 0x05,
    CMD_DELETE              = 0x06,
    CMD_TEST                = 0x07,
};

enum {
    CMD_KEY_GENETARE        = 0x70000001,
    CMD_KEY_SEARCH          = 0x70000002,
    CMD_KEY_DELETE          = 0x70000003,
    CMD_KCM_REPLY           = 0x70000004,
    CMD_CLEAR_CACHE         = 0x70000005,
    CMD_DEBUG               = 0x70000006
};

typedef struct _tagHashValues{
    char mem_hash[HASH_SIZE];
    char img_hash[HASH_SIZE];
} HashValue;

typedef struct _tagCmdNode{
    int32_t     cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    TEE_UUID    masterkey;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
}CmdNode;

typedef struct _tagReplyNode{
    int32_t tag;    //a tag to identify reply: 1 for generate reply, 2 for delete reply
    TEE_UUID    taId;
    TEE_UUID    keyId;
    union {
        uint8_t keyvalue[KEY_SIZE];
        int32_t flag;   //a flag to identify if the key is deleted successfully: 1 for deleted, 0 for not
    };
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next reply for search operation.
} ReplyNode;

TEE_UUID localUuid = {
    0xbbb2d138, 0xee21, 0x43af, { 0x87, 0x96, 0x40, 0xc2, 0x0d, 0x7b, 0x45, 0xfa }
};
TEE_UUID ktaUuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};
TEE_UUID randomKeyid = {
    0x11111111, 0x2222, 0x3333, { 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb }
};
uint32_t new_key_flag = 1;

uint8_t account[MAX_STR_LEN] = "1234";
uint8_t password[MAX_STR_LEN] = "5678";
uint8_t wrong_account[MAX_STR_LEN] = "1111";
uint8_t wrong_password[MAX_STR_LEN] = "2222";

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


#define VALUE_INIT 0x7fffffff
#define TIMEOUT 0x00000BB8

static const TEE_UUID ktauuid = {0x435dcafa, 0x0029, 0x4d53, {0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e}};

static const uint32_t session_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

void cmd_copy(CmdNode *cmdnode, TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey) {
    strncpy_s((char*)cmdnode->account, MAX_STR_LEN, (char*)account, MAX_STR_LEN);
    strncpy_s((char*)cmdnode->password, MAX_STR_LEN, (char*)password, MAX_STR_LEN);
    memcpy_s(&cmdnode->taId, sizeof(TEE_UUID), uuid, sizeof(TEE_UUID));
    if(keyid != NULL) {
        memcpy_s(&cmdnode->keyId, sizeof(TEE_UUID), keyid, sizeof(TEE_UUID));
    }
    if(masterkey != NULL) {
        memcpy_s(&cmdnode->masterkey, sizeof(TEE_UUID), masterkey, sizeof(TEE_UUID));
    }
}

void hex2char(uint32_t hex, uint8_t *hexchar, int32_t i) {
    tlogd("hex2char in test ta\n");
    for(i--; i >= 0; i--, hex >>= 4) {
        if ((hex & 0xf) <= 9)
            *(hexchar + i) = (hex & 0xf) + '0';
        else
            *(hexchar + i) = (hex & 0xf) + 'a' - 0x0a;
    }
}

void uuid2char(TEE_UUID uuid, uint8_t charuuid[37]) {
    tlogd("uuid2char in test ta\n");
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
    tlogd("char2uuid in test ta\n");
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
TEE_Result Encrypt(uint8_t *keyvalue) {
    tlogd("encrypt in test ta\n");
    char *data = "demo data";
    (void)keyvalue;
    (void)data;
    return TEE_SUCCESS;
}

TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *masterkey, char *mem_hash, char *img_hash) {
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    HashValue hash = {0};
    strncpy_s(hash.mem_hash, HASH_SIZE, mem_hash, strlen(mem_hash));
    strncpy_s(hash.img_hash, HASH_SIZE, img_hash, strlen(img_hash));

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, NULL, masterkey);
    cmdnode->cmd = CMD_KEY_GENETARE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(CmdNode);
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    params[PARAMETER_FOURTH].memref.buffer = &hash;
    params[PARAMETER_FOURTH].memref.size = sizeof(hash);
    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_KEY_GENETARE, command_param_type, params, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command generate key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return ret;
    }
    if(params[PARAMETER_THIRD].value.b != 1) {
        tloge("generate kcm command failed");
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return TEE_ERROR_CANCEL;
    }
    
    tlogd("success to create a command of generating a key");
    TEE_CloseTASession(session);
    TEE_Free(cmdnode);
    return TEE_SUCCESS;
}

TEE_Result search_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid,
        TEE_UUID *masterkey, uint8_t *keyvalue, uint32_t *flag, char *mem_hash, char *img_hash) {
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    HashValue hash = {0};
    strncpy_s(hash.mem_hash, HASH_SIZE, mem_hash, strlen(mem_hash));
    strncpy_s(hash.img_hash, HASH_SIZE, img_hash, strlen(img_hash));

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, keyid, masterkey);
    cmdnode->cmd = CMD_KEY_SEARCH;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(CmdNode);
    params[PARAMETER_SECOND].memref.buffer = keyvalue;
    params[PARAMETER_SECOND].memref.size = KEY_SIZE;
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    params[PARAMETER_FOURTH].memref.buffer = &hash;
    params[PARAMETER_FOURTH].memref.size = sizeof(hash);

    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_KEY_SEARCH, command_param_type, params, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command search key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return ret;
    }
    if(params[PARAMETER_THIRD].value.a == 0) {
        tlogd("success to search key");
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return TEE_SUCCESS;
    }
    if(params[PARAMETER_THIRD].value.a != 1 || params[PARAMETER_THIRD].value.b != 1) {
        tloge("generate kcm command failed");
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return TEE_ERROR_BAD_FORMAT;
    }
    *flag = 1;
    TEE_CloseTASession(session);
    TEE_Free(cmdnode);
    return TEE_SUCCESS;
}

TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid,
        char *mem_hash, char *img_hash) {
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    HashValue hash = {0};
    strncpy_s(hash.mem_hash, HASH_SIZE, mem_hash, strlen(mem_hash));
    strncpy_s(hash.img_hash, HASH_SIZE, img_hash, strlen(img_hash));

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, keyid, NULL);
    cmdnode->cmd = CMD_KEY_DELETE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_INPUT);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(CmdNode);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    params[PARAMETER_FOURTH].memref.buffer = &hash;
    params[PARAMETER_FOURTH].memref.size = sizeof(hash);

    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_KEY_DELETE, command_param_type, params, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command destory key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return ret;
    }
    if(params[PARAMETER_SECOND].value.a != 1) {
        tloge("delete local key failed");
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return TEE_ERROR_CANCEL;
    }
    if(params[PARAMETER_THIRD].value.a != 1) {
        tloge("generate kcm command failed");
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return TEE_ERROR_BAD_FORMAT;
    }

    tlogd("success generate destory key command");
    TEE_CloseTASession(session);
    TEE_Free(cmdnode);
    return TEE_SUCCESS;
}

TEE_Result clear_cache(TEE_UUID *uuid, uint8_t *account, uint8_t *password,
        char *mem_hash, char *img_hash) {
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    HashValue hash = {0};
    strncpy_s(hash.mem_hash, HASH_SIZE, mem_hash, strlen(mem_hash));
    strncpy_s(hash.img_hash, HASH_SIZE, img_hash, strlen(img_hash));

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        return ret;
    }

    cmd_copy(cmdnode, uuid, account, password, NULL, NULL);
    cmdnode->cmd = CMD_CLEAR_CACHE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_MEMREF_INPUT);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(CmdNode);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    params[PARAMETER_FOURTH].memref.buffer = &hash;
    params[PARAMETER_FOURTH].memref.size = sizeof(hash);
    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_CLEAR_CACHE, command_param_type, params, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command clear cache failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        TEE_CloseTASession(session);
        return ret;
    }
    if(params[PARAMETER_SECOND].value.a != 1) {
        tloge("clear local cache failed");
        TEE_CloseTASession(session);
        TEE_Free(cmdnode);
        return TEE_ERROR_CANCEL;
    }

    tlogd("success to clear cache");
    TEE_CloseTASession(session);
    TEE_Free(cmdnode);
    return TEE_SUCCESS;
}

TEE_Result get_kcm_reply(TEE_UUID *uuid, uint8_t *account, uint8_t *password,
        TEE_UUID *keyid, uint8_t *keyvalue, char *mem_hash, char *img_hash) {
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    ReplyNode *replynode = TEE_Malloc(sizeof(ReplyNode), 0);
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    HashValue hash = {0};
    strncpy_s(hash.mem_hash, HASH_SIZE, mem_hash, strlen(mem_hash));
    strncpy_s(hash.img_hash, HASH_SIZE, img_hash, strlen(img_hash));

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        return ret;
    }
    
    cmd_copy(cmdnode, uuid, account, password, NULL, NULL);
    cmdnode->cmd = CMD_KCM_REPLY;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_MEMREF_INPUT);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(CmdNode);
    params[PARAMETER_SECOND].memref.buffer = replynode;
    params[PARAMETER_SECOND].memref.size = sizeof(ReplyNode);
    params[PARAMETER_FOURTH].memref.buffer = &hash;
    params[PARAMETER_FOURTH].memref.size = sizeof(hash);
    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_KCM_REPLY, command_param_type, params, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command get kcm reply failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        TEE_Free(replynode);
        TEE_CloseTASession(session);
        return ret;
    }
    switch(replynode->tag) {
        case 1:
        memcpy_s(keyid, sizeof(TEE_UUID), &replynode->keyId, sizeof(TEE_UUID));
        memcpy_s(keyvalue, KEY_SIZE, replynode->keyvalue, KEY_SIZE);
        TEE_Free(cmdnode);
        TEE_Free(replynode);
        return TEE_SUCCESS;
        case 2:
        tlogd("get a key delete reply");
        if(replynode->flag) {
            TEE_Free(cmdnode);
            TEE_Free(replynode);
            return TEE_SUCCESS;
        } else {
            TEE_Free(cmdnode);
            TEE_Free(replynode);
            return TEE_ERROR_NOT_IMPLEMENTED;
        }
    }
    TEE_Free(cmdnode);
    TEE_Free(replynode);
    return TEE_SUCCESS;
}

TEE_Result CAPart(){
    TEE_Result ret;
    CmdNode *cmdnode = TEE_Malloc(sizeof(CmdNode), 0);
    TEE_TASessionHandle session = {0};
    uint32_t retOrigin = 0;

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_Free(cmdnode);
        return ret;
    }

    ret = TEE_InvokeTACommand(session, TIMEOUT, CMD_DEBUG, session_param_type, NULL, &retOrigin);
    if(ret != TEE_SUCCESS) {
        tlogd("invoke command debug failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    TEE_CloseTASession(session);
    return TEE_SUCCESS;
}

TEE_Result testKeyGenerate(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testKeyGenerate in test ta\n");
    TEE_Result ret;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE ||
        params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("test generate_key-------------------------------------");
    ret = generate_key(&localUuid, account, password, &masterkey, mem_hash, img_hash);
    if(ret != TEE_SUCCESS) {
        tloge("generate key command failed");
        return ret;
    }
    params[PARAMETER_FOURTH].value.a = 1;
    flag.symbol = 1;
    //new_key_flag -= 1;
    new_key_flag = 0;
    tlogd("prepare to encrypt data success");
    return TEE_SUCCESS;
}

TEE_Result testGetKeyGenerateReply(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testGetKeyGenerateReply in test ta\n");
    TEE_Result ret;
    TEE_UUID keyid = {0};
    char keyidchar[37] = {0};
    uint8_t *keyvalue = NULL;
    TEE_ObjectHandle keyid_data = NULL;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE ||
        params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("test get_kcm_reply------------------------------------------------------");
    ret = get_kcm_reply(&localUuid, account, password, &keyid, keyvalue, mem_hash, img_hash);
    if (ret != TEE_SUCCESS) {
        tloge("get generate key reply failed");
        return ret;
    }
    tlogd("get generate key reply success");
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
    params[PARAMETER_FOURTH].value.a = 0;
    TEE_CloseObject(keyid_data);

    Encrypt(keyvalue);
    tlogd("encrypt data success");
    tlogd("execute call back success");
    return TEE_SUCCESS;
}

TEE_Result testSearchKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testDeleteKey in test ta\n");
    TEE_Result ret;
    uint8_t *keyvalue = NULL;
    //A flag indicating whether a new key is required
    TEE_UUID keyid = {0};
    TEE_ObjectHandle keyid_data = NULL;
    uint32_t len = 36, count = 0;
    int8_t *keyidchar = NULL;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE ||
        params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("prepare to encrypt data");
    uint32_t twice_search_flag = 0;

    tlogd("new_key_flag is 0, test search_key---------------------------------------");
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
    ret = search_key(&localUuid, account, password, &randomKeyid, &masterkey, keyvalue, &twice_search_flag, mem_hash, img_hash);
    if(ret != TEE_SUCCESS) {
        tlogd("search command failed");
        return ret;
    } else {
        tlogd("search command succeeded");
    }

    Encrypt(keyvalue);
    TEE_Free(keyvalue);
    tlogd("encrypt data success");
    params[PARAMETER_FOURTH].value.a = 0;
    return TEE_SUCCESS;
}

TEE_Result delete_key_opt(TEE_UUID *keyid, TEE_Param params[PARAM_COUNT] ) {
    tlogd("delete_key_opt in test ta\n");
    TEE_Result ret;
    /*ret = delete_key(NULL, NULL, NULL, NULL);
    if(ret != TEE_SUCCESS) {
        tlogd("result of delete_key with NULL values is not TEE_SUCCESS");
    }*/
    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    tlogd("test delete_key-------------------------------------------------------");
    ret = delete_key(&localUuid, account, password, keyid, mem_hash, img_hash);
    if (ret != TEE_SUCCESS) {
        tloge("delete key failed");
        return ret;
    }
    /*tlogd("test delete_key for a second time with same parameters----------------");
    ret = delete_key(&localUuid, account, password, keyid, mem_hash, img_hash);
    if (ret != TEE_SUCCESS) {
        tloge("delete key failed at the second time------------------------------");
        return ret;
    }*/
    params[PARAMETER_FOURTH].value.a = 1;
    flag.symbol = 3;
    return TEE_SUCCESS;
}

TEE_Result testDeleteKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testDeleteKey in test ta\n");
    TEE_Result ret;
    //A flag indicating whether a new key is required
    TEE_UUID keyid = {0};
    TEE_ObjectHandle keyid_data = NULL;
    uint32_t len = 36, count = 0;
    int8_t *keyidchar = NULL;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE ||
        params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("new_key_flag is 0, test delete_key---------------------------------------");
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

    tlogd("encrypt data success");
    ret = delete_key_opt(&keyid, params);
    if (ret != TEE_SUCCESS) {
        tloge("generate delete cmd fail");
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result testGetKeyDeleteReply(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testGetKeyDeleteReply in test ta\n");
    TEE_Result ret;
    TEE_UUID keyid = {0};
    uint8_t *keyvalue = NULL;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE ||
        params[PARAMETER_FOURTH].value.a != 0x7fffffff) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogd("test get_kcm_reply------------------------------------------------------");
    ret = get_kcm_reply(&localUuid, account, password, &keyid, NULL, mem_hash, img_hash);
    if (ret != TEE_SUCCESS) {
        params[PARAMETER_FOURTH].value.a = 2;
        tloge("delete key failed");
        return ret;
    } else {
        params[PARAMETER_FOURTH].value.a = 0;
        tlogd("delete key success");
        return TEE_SUCCESS;
    }

    Encrypt(keyvalue);
    tlogd("execute call back success");
    return TEE_SUCCESS;
}

TEE_Result ta_exit(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("ta_exit in test ta\n");
    TEE_Result ret;
    TEE_ObjectHandle keyid_data = NULL;

    char mem_hash[HASH_SIZE] = {0};
    char img_hash[HASH_SIZE] = {0};
    strncpy_s(mem_hash, HASH_SIZE, params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    strncpy_s(img_hash, HASH_SIZE, params[PARAMETER_SECOND].memref.buffer, params[PARAMETER_SECOND].memref.size);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size != HASH_SIZE ||
        params[PARAMETER_SECOND].memref.buffer == NULL ||
        params[PARAMETER_SECOND].memref.size != HASH_SIZE) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*ret = clear_cache(NULL, NULL, NULL);
    if(ret != TEE_SUCCESS) {
        tlogd("result of clear_cache with NULL values is not TEE_SUCCESS");
    }*/
    tlogd("test clear_cache------------------------------------------------------------");
    ret = clear_cache(&localUuid, account, password, mem_hash, img_hash);
    if(ret != TEE_SUCCESS) {
        tloge("clear cache failed");
        return ret;
    }
    /*tlogd("test clear_cache for a second time------------------------------------------");
    ret = clear_cache(&localUuid, account, password, mem_hash, img_hash);
    if(ret == TEE_SUCCESS) {
        tloge("clear cache failed at the second time-----------------------------------");
        return ret;
    }*/
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

TEE_Result testCAPart(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    tlogd("testCAPart in test ta\n");
    TEE_Result ret;

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

    tlogd("test CA part of kta-----------------------------------------------");
    ret = CAPart();
    if(ret != TEE_SUCCESS) {
        tlogd("test ca part of kta failed");
    }
    return ret;
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogd("TA_CreateEntryPoint in test ta\n");
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
    tlogd("TA_OpenSessionEntryPoint in test ta\n");
    (void)parm_type;
    (void)params;
    (void)session_context;
    tlogd("open session success");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void* session_context, uint32_t cmd,
    uint32_t param_type, TEE_Param params[PARAM_COUNT])
{
    tlogd("TA_InvokeCommandEntryPoint in test ta\n");
    TEE_Result ret;
    (void)session_context;

    tlogd("---- TA invoke command ----------- ");
    switch (cmd) {
    case CMD_GENERATE:
        ret = testKeyGenerate(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("key generate failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_GENERATE_CALLBACK:
        ret = testGetKeyGenerateReply(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("key generate call back failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_TA_EXIT:
        ret = ta_exit(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("execute ta exit operation failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_SEARCH:
        ret = testSearchKey(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("key search failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_DELETE_CALLBACK:
        ret = testGetKeyDeleteReply(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("key delete call back failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_DELETE:
        ret = testDeleteKey(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("key delete failed0x%x", ret);
            return ret;
        }
        break;
    case CMD_TEST:
        ret = testCAPart(param_type, params);
        if(ret != TEE_SUCCESS) {
            tloge("execute test ca part failed0x%x", ret);
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
    tlogd("TA_CloseSessionEntryPoint in test ta\n");
    (void)session_context;
    tlogd("---- close session ----- ");
}

void TA_DestroyEntryPoint(void){
    tlogd("TA_DestroyEntryPoint in test ta\n");
    tlogd("---- destory TA ---- ");
}
