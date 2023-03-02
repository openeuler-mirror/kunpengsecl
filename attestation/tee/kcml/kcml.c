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

#include <tee_defines.h>
#include <tee_log.h>
#include <tee_core_api.h>
#include <tee_time_api.h>
#include <tee_mem_mgmt_api.h>
#include <securec.h>
#include "kcml.h"

#define VALUE_INIT 0x7fffffff
#define TIMEOUT 0x00000BB8

static const TEE_UUID ktauuid = {0x435dcafa, 0x0029, 0x4d53, {0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e}};

static const uint32_t session_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

void cmd_copy(CmdNode *cmdnode, TEE_UUID *uuid, uint8_t *account, uint8_t *password,
        TEE_UUID *keyid, TEE_UUID *masterkey) {
    strncpy_s((char*)cmdnode->account, MAX_STR_LEN, (char*)account, strlen((char*)account));
    strncpy_s((char*)cmdnode->password, MAX_STR_LEN, (char*)password, strlen((char*)password));
    memcpy_s(&cmdnode->taId, sizeof(TEE_UUID), uuid, sizeof(TEE_UUID));
    if(keyid != NULL) {
        memcpy_s(&cmdnode->keyId, sizeof(TEE_UUID), keyid, sizeof(TEE_UUID));
    }
    if(masterkey != NULL) {
        memcpy_s(&cmdnode->masterkey, sizeof(TEE_UUID), masterkey, sizeof(TEE_UUID));
    }
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