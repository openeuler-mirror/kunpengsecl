/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun
Create: 2022-11-02
Description: kta manages the TA's key cache in the TEE.
	1. 2022-11-02	wucaijun
		prepare the init code.
*/

#include <tee_ext_api.h>
#include <tee_log.h>
#include <kta_command.h>

#define PARAM_COUNT 4

enum {
    CMD_KTA_INITIALIZE      = 0x00000001,
    CMD_SEND_REQUEST        = 0x00000002,
    CMD_RESPOND_REQUEST     = 0x00000003,
    CMD_KEY_INIT            = 0x80000001,
    CMD_KEY_SEARCH          = 0x80000002,
    CMD_KEY_DELETE          = 0x80000003,
    CMD_KEY_DESTORY         = 0x80000004,
    CMD_KEY_REPLY           = 0x80000005,
};

Cache *cache = {0};
CmdQueue *cmdqueue = {0};

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    tlogd("----- TA entry point ----- ");

    ret = addcaller_ca_exec("", "");  //需要确定ca的路径
    if (ret == TEE_SUCCESS) 
        tlogd("TA entry point: add ca whitelist success");
    else {
        tloge("TA entry point: add ca whitelist failed");
        return ret;
    }
    ret = AddCaller_TA_all();
    if (ret == TEE_SUCCESS)
        tlogd("TA entry point: add ta caller success");
    else {
        tloge("TA entry point: add ta caller failed");
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parm_type,
    TEE_Param params[PARAM_COUNT], void** session_context) {
    
    TEE_Result ret;

    (void)parm_type;
    (void)params;
    (void)session_context;
    tlogd("---- TA open session -------- ");

    return TEE_SUCCESS;
}

//this function maybe needs to be modified according to ta and ka workflow
TEE_Result TA_InvokeCommandEntryPoint(void* session_context, uint32_t cmd,
    uint32_t parm_type, TEE_Param params[PARAM_COUNT])
{
    TEE_Result ret;
    TEE_UUID uuid = {0};
    caller_info caller_info = {0};
    void *teepubkey = {0};
    void *signedpubkey = {0};
    void *keyvalue = {0};
    char keyid[32] = {0};

    (void)session_context;

    tlogd("---- TA invoke command ----------- ");
    ret = TEE_EXT_GetCallerInfo(&caller_info, sizeof(caller_info));
    if (caller_info.session_type == SESSION_FROM_CA) {
        switch (cmd) {
        case CMD_KTA_INITIALIZE:
            ret = KTAInitialize( parm_type, params );
            if (ret != TEE_SUCCESS)
                tloge("initialize kta failed\n");
            return ret;
            break;
        case CMD_SEND_REQUEST:
            ret = SendRequest(cmd, params);
            if (ret != TEE_SUCCESS)
                tloge("send ta requests failed\n");
            return ret;
            break;
        case CMD_RESPOND_REQUEST:
            ret = GetResponse(cmd, params);
            if (ret != TEE_SUCCESS)
                tloge("handle ka response failed\n");
            return ret;
            break;
        default:
            tloge("Unknown cmd is %u", cmd);
            ret = TEE_ERROR_BAD_PARAMETERS;
        }
    } else if (caller_info.session_type == SESSION_FROM_TA) {
        switch (cmd) {
        case CMD_KEY_INIT:
            ret = InitTAKey(uuid, cache);
            if (ret != TEE_SUCCESS)
                tloge("init ta failed\n");
            return ret;
            break;
        case CMD_KEY_SEARCH:
            ret = SearchTAKey(uuid, keyid, cache, keyvalue);
            if (ret != TEE_SUCCESS)
                tloge("search ta key failed\n");
            return ret;
            break;
        case CMD_KEY_DELETE:
            ret = DeleteTAKey(uuid, keyid, cache);
            if (ret != TEE_SUCCESS)
                tloge("delete ta key failed\n");
            return ret;
            break;
        case CMD_KEY_DESTORY:
            ret = DestoryTAKey(uuid, keyid, cache);
            if (ret != TEE_SUCCESS)
                tloge("destory ta key failed\n");
            return ret;
            break;
        case CMD_KEY_REPLY:
            ret = SendReplytoTA();
            if (ret != TEE_SUCCESS)
                tloge("get kta's reply failed\n");
            return ret;
            break;
        default:
            tloge("Unknown cmd is %u", cmd);
            ret = TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        tloge("judge caller session failed\n");
        return TEE_ERROR_SESSION_NOT_EXIST;
    }
    return ret;
}

void TA_CloseSessionEntryPoint(void* session_context){
    (void)session_context;
    tlogd("---- close session ----- ");
}

void TA_DestroyEntryPoint(void){
    tlogd("---- destory TA ---- ");
}
