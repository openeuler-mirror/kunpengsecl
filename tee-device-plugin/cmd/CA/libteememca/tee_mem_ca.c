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
 * Description: the CA part to call TA for the tee memory.
 */
#include <limits.h>
#include <time.h>
#include "tee_mem_ca.h"
#include "tee_client_api.h"

#define TA_PATH "/data/e3d37f4a-f24c-48d0-8884-3bdd6c44e988.sec"
#define CMD_GET_MEMORY 0
#define PARAM_COUNT 4
#define MEM_INFO_COUNT 2
#define K_BYTES 1024
#define RESERVE_MEMORY (600 * K_BYTES)
#define PARAM_IDX0 0
#define PARAM_IDX3 3

static void GetSysTime(void);
#define LOG_ERROR(format, args...)                \
    do {                                          \
        GetSysTime();                             \
        fprintf(stderr, " " format "\n", ##args); \
    } while (0)

typedef struct {
    uint64_t totalMem;
    uint64_t freeMem;
} MemInfo;

static const TEEC_UUID TA_uuid = {
    0xe3d37f4a, 0xf24c, 0x48d0, {0x88, 0x84, 0x3b, 0xdd, 0x6c, 0x44, 0xe9, 0x88}
};
static TEEC_Context g_context;
static TEEC_Session g_session;

static void GetSysTime(void)
{
    time_t rawTime = {0};
    struct tm *info = NULL;

    (void)time(&rawTime);
    if ((info = localtime(&rawTime)) == NULL) {
        return;
    }

    fprintf(stderr, "%d/%02d/%02d %02d:%02d:%02d", 1900 + info->tm_year,
            info->tm_mon, info->tm_mday, info->tm_hour, info->tm_min, info->tm_sec);
}

static TEEC_Result TeecInit(void)
{
    TEEC_Operation opt = {0};
    TEEC_Result ret = TEEC_SUCCESS;
    uint32_t origin = 0;

    ret = TEEC_InitializeContext(NULL, &g_context);
    if (ret != TEEC_SUCCESS) {
        LOG_ERROR("Teec initial context failed.");
        return ret;
    }

    opt.started = 1;
    opt.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    g_context.ta_path = (uint8_t *)TA_PATH;
    ret = TEEC_OpenSession(&g_context, &g_session, &TA_uuid, TEEC_LOGIN_IDENTIFY, NULL, &opt, &origin);
    if (ret != TEEC_SUCCESS) {
        LOG_ERROR("Teec open session failed. result: %x origin: %u.", (uint32_t)ret, origin);
        TEEC_FinalizeContext(&g_context);
    }

    return ret;
}

static TEEC_Result TeecClose(void)
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);
}

static bool CheckMultiplyOverflow(uint64_t v1, uint32_t v2)
{
    if (v1 != 0 && LONG_MAX / v1 < v2) {
        LOG_ERROR("Integer multiply overflow");
        return true;
    }
    return false;
}

static TEEC_Result CmdGetMemInfo(MemInfo *mem)
{
    TEEC_Operation opt = {0};
    TEEC_Result ret = TEEC_SUCCESS;
    uint32_t origin = 0;
    uint64_t memValArr[MEM_INFO_COUNT] = {0};

    opt.started = 1;
    opt.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_OUTPUT);
    opt.params[PARAM_IDX0].tmpref.buffer = memValArr;
    opt.params[PARAM_IDX0].tmpref.size = MEM_INFO_COUNT * sizeof(uint64_t);
    ret = TEEC_InvokeCommand(&g_session, CMD_GET_MEMORY, &opt, &origin);
    if (ret != TEEC_SUCCESS) {
        LOG_ERROR("Teec get memory failed. result: %x origin: %u.", (uint32_t)ret, origin);
        return ret;
    }

    for (int i = 0; i < MEM_INFO_COUNT; i++) {
        memValArr[i] /= K_BYTES;
    }
    if (CheckMultiplyOverflow(memValArr[0], opt.params[3].value.a) ||
        CheckMultiplyOverflow(memValArr[1], opt.params[3].value.a)) {
        return TEEC_FAIL;
    }
    mem->totalMem = memValArr[0] * opt.params[PARAM_IDX3].value.a;
    mem->freeMem = memValArr[1] * opt.params[PARAM_IDX3].value.a;

    return ret;
}

static int GetMemInfo(MemInfo *mem)
{
    int ret = -1;

    if (TeecInit() != TEEC_SUCCESS) {
        return ret;
    }
    if (CmdGetMemInfo(mem) == TEEC_SUCCESS) {
        ret = 0;
    }
    TeecClose();

    return ret;
}

long long GetTeeCapacityMem(void)
{
    MemInfo mem = {0};

    if (GetMemInfo(&mem) != 0) {
        return -1;
    }
    if (mem.totalMem <= RESERVE_MEMORY) {
        LOG_ERROR("Total Memory is less than reserve memory");
        return -1;
    }

    return mem.totalMem - RESERVE_MEMORY;
}

long long GetTeeFreeMem(void)
{
    MemInfo mem = {0};

    if (GetMemInfo(&mem) != 0) {
        return -1;
    }

    return mem.freeMem;
}