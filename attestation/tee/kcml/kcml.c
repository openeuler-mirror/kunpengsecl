#include <tee_defines.h>
#include <tee_core_api.h>
#include <tee_time_api.h>
#include <securec.h>
#include "kcml.h"

#define VALUE_INIT 0x8fffffff
#define TIMEOUT 0x00000BB8

static const TEE_UUID ktauuid = {0x435dcafa, 0x0029, 0x4d53, {0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e}};

static const session_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

void cmd_copy(CmdData *cmddata, TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey) {
    strncpy_s((char*)cmddata->account, MAX_STR_LEN, (char*)account, MAX_STR_LEN);
    memcpy_s((void*)&cmddata->taId, sizeof(TEE_UUID), (void*)uuid, sizeof(TEE_UUID));
    memcpy_s((void*)&cmddata->keyId, sizeof(TEE_UUID), (void*)keyid, sizeof(TEE_UUID));
    memcpy_s((void*)&cmddata->masterkey, sizeof(TEE_UUID), (void*)masterkey, sizeof(TEE_UUID));
    strncpy_s((char*)cmddata->password, MAX_STR_LEN, (char*)password, MAX_STR_LEN);
}

TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *masterkey, uint8_t *keyvalue) {
    TEE_Result ret;
    CmdData *cmddata;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 0;
    uint32_t command_param_type = 0;

    TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmddata, uuid, account, password, NULL, masterkey);
    cmddata->cmd = CMD_KEY_GENETARE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
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
    ret = TEE_Wait(2000);
    if(ret != TEE_SUCCESS) {
        tloge("invoke time wait failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }

    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
    params[PARAMETER_SECOND].memref.buffer = keyvalue;
    params[PARAMETER_SECOND].memref.size = KEY_SIZE * sizeof(keyvalue);
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KCM_REPLY, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command get kcm reply failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    tlogd("success to generate new key");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result search_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey , uint8_t *keyvalue) {
    TEE_Result ret;
    CmdData *cmddata;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    TEE_Param symbol = {0};
    uint32_t retOrigin = 1;
    uint32_t command_param_type = 0;

    TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmddata, uuid, account, password, keyid, masterkey);
    cmddata->cmd = CMD_KEY_SEARCH;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
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
    
    ret = TEE_Wait(2000);
    if(ret != TEE_SUCCESS) {
        tloge("invoke time wait failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }

    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
    params[PARAMETER_SECOND].memref.buffer = keyvalue;
    params[PARAMETER_SECOND].memref.size = KEY_SIZE * sizeof(keyvalue);
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_SEARCH, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command search key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_THIRD].value.a != 0) {
        tloge("search TA key failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_TIMEOUT;
    }
    tlogd("success to search key");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid) {
    TEE_Result ret;
    CmdData *cmddata;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 2;
    uint32_t command_param_type = 0;

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmddata, uuid, account, password, keyid, NULL);
    cmddata->cmd = CMD_KEY_DELETE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;
    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_DELETE, command_param_type, params, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("invoke command delete key failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        TEE_CloseTASession(&session);
        return ret;
    }
    if(params[PARAMETER_SECOND].value.a != 1 || params[PARAMETER_THIRD].value.a != 0) {
        tloge("delete local key failed");
        TEE_CloseTASession(&session);
        return TEE_ERROR_CANCEL;
    }
    tlogd("success to delete key");
    TEE_CloseTASession(&session);
    return TEE_SUCCESS;
}

TEE_Result destory_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid) {
    TEE_Result ret;
    CmdData *cmddata;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 3;
    uint32_t command_param_type = 0;
    uint32_t *destory_flag = VALUE_INIT;
    uint32_t flag_size = sizeof(uint32_t*);

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }
    cmd_copy(cmddata, uuid, account, password, keyid, NULL);
    cmddata->cmd = CMD_KEY_DESTORY;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
    params[PARAMETER_SECOND].value.a = VALUE_INIT;
    params[PARAMETER_SECOND].value.b = VALUE_INIT;
    params[PARAMETER_THIRD].value.a = VALUE_INIT;
    params[PARAMETER_THIRD].value.b = VALUE_INIT;

    ret = TEE_InvokeTACommand(&session, TIMEOUT, CMD_KEY_DESTORY, command_param_type, params, retOrigin);
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
    CmdData *cmddata;
    TEE_TASessionHandle session = {0};
    TEE_Param params[4] = {0};
    uint32_t retOrigin = 4;
    uint32_t command_param_type = 0;

    ret = TEE_OpenTASession(&ktauuid, TIMEOUT, session_param_type, NULL, &session, retOrigin);
    if(ret != TEE_SUCCESS) {
        tloge("open ta session failed, origin=0x%x, codes=0x%x\n", retOrigin, ret);
        return ret;
    }

    cmd_copy(cmddata, uuid, account, password, NULL, NULL);
    cmddata->cmd = CMD_CLEAR_CACHE;
    command_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    params[PARAMETER_FRIST].memref.buffer = cmddata;
    params[PARAMETER_FRIST].memref.size = sizeof(cmddata);
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
//TEE_Result get_key_reply(uint8_t *keyvalue);