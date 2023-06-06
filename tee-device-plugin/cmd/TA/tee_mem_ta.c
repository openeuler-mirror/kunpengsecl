/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 *
 * kunpengsecl licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of
 * the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: chenzheng
 * Create: 2023-04-23
 * Description: the TA part to get the tee memory.
 */
#include <linux/kernel.h>
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"

#define TA_VERSION "V1"
#define CMD_GET_MEMORY 0
#define PARAM_COUNT 4
#define MEM_INFO_COUNT 2
#define PARAM_IDX0 0
#define PARAM_IDX3 3

extern int sysinfo(struct sysinfo *__info);

static TEE_Result GetMemInfo(uint32_t parm_type, TEE_Param params[PARAM_COUNT])
{
    struct sysinfo memInfo = {0};
    int err = 0;
    uint64_t *memValArr = NULL;
    size_t len = sizeof(uint64_t) * MEM_INFO_COUNT;

    if (!check_param_type(parm_type, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        SLogError("Bad expected parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAM_IDX0].memref.buffer == NULL || params[PARAM_IDX0].memref.size < len) {
        SLogError("Bad expected memref value");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((err = sysinfo(&memInfo)) != 0) {
        SLogError("Call sysinfo failed, err = %d", err);
        return TEE_FAIL;
    }

    memValArr = (uint64_t *)params[0].memref.buffer;
    memValArr[0] = memInfo.totalram;
    memValArr[1] = memInfo.freeram;
    params[PARAM_IDX0].memref.size = len;
    params[PARAM_IDX3].value.a = memInfo.mem_unit;

    return TEE_SUCCESS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    SLogTrace("----- TA_CreateEntryPoint ----- ");
    SLogTrace("TA version: %s", TA_VERSION);

    ret = addcaller_ca_exec("/vendor/bin/tee-device-plugin", "root");
    if (ret == TEE_SUCCESS) {
        SLogTrace("TA entry point: add ca whitelist success");
    } else {
        SLogError("TA entry point: add ca whitelist failed");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parm_type, TEE_Param params[PARAM_COUNT],
    void **session_context)
{
    (void)parm_type;
    (void)params;
    (void)session_context;
    SLogTrace("---- TA_OpenSessionEntryPoint -------- ");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd,
    uint32_t parm_type, TEE_Param params[PARAM_COUNT])
{
    (void)session_context;
    TEE_Result ret;

    SLogTrace("---- TA_InvokeCommandEntryPoint ----------- ");
    switch (cmd) {
    case CMD_GET_MEMORY:
        ret = GetMemInfo(parm_type, params);
        break;
    default:
        SLogError("Unknown cmd is %u", cmd);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }

    return ret;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
    (void)session_context;
    SLogTrace("---- TA_CloseSessionEntryPoint ----- ");
}

void TA_DestroyEntryPoint(void)
{
    SLogTrace("---- TA_DestroyEntryPoint ---- ");
}
