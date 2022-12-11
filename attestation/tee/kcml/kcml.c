#include <tee_defines.h>
#include <tee_core_api.h>
#include <tee_time_api.h>
#include <securec.h>
#include "kcml.h"

#define VALUE_INIT 0x8fffffff
#define TIMEOUT 0x00000BB8
#define KEY_SIZE 8192

static const TEE_UUID ktauuid = {0x435dcafa, 0x0029, 0x4d53, {0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e}};

static const session_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

typedef struct _tagReplyData{
    TEE_UUID    taId;
    TEE_UUID    keyId;
    uint8_t keyvalue[KEY_SIZE];
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next reply for search operation.
} ReplyNode;

void cmd_copy(CmdNode *cmdnode, TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey) {
    strncpy_s((char*)cmdnode->account, MAX_STR_LEN, (char*)account, MAX_STR_LEN);
    memcpy_s((void*)&cmdnode->taId, sizeof(TEE_UUID), (void*)uuid, sizeof(TEE_UUID));
    memcpy_s((void*)&cmdnode->keyId, sizeof(TEE_UUID), (void*)keyid, sizeof(TEE_UUID));
    memcpy_s((void*)&cmdnode->masterkey, sizeof(TEE_UUID), (void*)masterkey, sizeof(TEE_UUID));
    strncpy_s((char*)cmdnode->password, MAX_STR_LEN, (char*)password, MAX_STR_LEN);
}

TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *masterkey) {
    TEE_Result ret;
    CmdNode *cmdnode;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;

    TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, NULL, masterkey);
    cmdnode->cmd = CMD_KEY_GENETARE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(cmdnode);
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_GENETARE, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command generate key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_THIRD].value.b != 1) {
        tloge("generate kcm command failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_CANCEL;
    }
    
    tlogd("success to create a command of generating a key");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result search_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey , uint8_t *keyvalue, uint32_t *flag) {
    TEE_Result ret;
    CmdNode *cmdnode;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    TEE_Param symbol = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;

    TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, keyid, masterkey);
    cmdnode->cmd = CMD_KEY_SEARCH;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(cmdnode);
    params[PARAMETER_SECOND].memref.buffer = keyvalue;
    params[PARAMETER_SECOND].memref.buffer = KEY_SIZE * sizeof(keyvalue);
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;

    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_SEARCH, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command search key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_THIRD].value.a == 0) {
        tlogd("success to search key");
        TEE_CloseTASession(&session);
        return TEE_SUCCESS;
    }
    if(params[PARAMETER_THIRD].value.a != 1 || params[PARAMETER_THIRD].value.b != 1) {
        tloge("generate kcm command failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_BAD_FORMAT;
    }
    *flag = 1;
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid) {
    TEE_Result ret;
    CmdNode *cmdnode;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;
    uint32_t *destory_flag = VALUE_INIT;
    uint32_t flag_size = sizeof(uint32_t*);

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmdnode, uuid, account, password, keyid, NULL);
    cmdnode->cmd = CMD_KEY_DELETE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(cmdnode);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;

    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_DELETE, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command destory key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_SECOND].value.a != 1) {
        tloge("delete local key failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_CANCEL;
    }
    if(params[PARAMETER_THIRD].value.b != 1) {
        tloge("generate kcm command failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_BAD_FORMAT;
    }

    tlogd("success to destory key");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result clear_cache(TEE_UUID *uuid, uint8_t *account, uint8_t *password) {
    TEE_Result ret;
    CmdNode *cmdnode;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }

    cmd_copy(cmdnode, uuid, account, password, NULL, NULL);
    cmdnode->cmd = CMD_CLEAR_CACHE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(cmdnode);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_CLEAR_CACHE, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command clear cache failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_SECOND].value.a != 1) {
        tloge("clear local cache failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_CANCEL;
    }

    tlogd("success to destory cache");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result get_key_reply(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey, uint8_t *keyvalue) {
    TEE_Result ret;
    CmdNode *cmdnode = NULL;
    ReplyNode *replynode = NULL;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;

    TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    
    cmd_copy(cmdnode, uuid, account, password, NULL, NULL);
    cmdnode->cmd = CMD_KCM_REPLY;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmdnode;
    params[PARAMETER_FRIST].memref.size = sizeof(cmdnode);
    params[PARAMETER_SECOND].memref.buffer = replynode;
    params[PARAMETER_SECOND].memref.size = sizeof(replynode);
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KCM_REPLY, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command get kcm reply failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    memcpy_s(keyid, sizeof(TEE_UUID), &replynode->keyId, sizeof(TEE_UUID));
    memcpy_s(keyvalue, KEY_SIZE, replynode->keyvalue, KEY_SIZE);
    tlogd("success to get key generation reply");
    return TEE_SUCCESS;
}