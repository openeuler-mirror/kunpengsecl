#include "tee_mem_ca.h"
#include "tee_client_api.h"

#define TA_PATH "/data/e3d37f4a-f24c-48d0-8884-3bdd6c44e988.sec"
#define CMD_GET_MEMORY 0
#define PARAM_COUNT 4
#define MEM_INFO_COUNT 2
#define K_BYTES 1024
#define RESERVE_MEMORY (300 * K_BYTES)

typedef struct {
    uint64_t totalMem;
    uint64_t freeMem;
} MemInfo;

static const TEEC_UUID TA_uuid = {
    0xe3d37f4a, 0xf24c, 0x48d0,
    {0x88, 0x84, 0x3b, 0xdd, 0x6c, 0x44, 0xe9, 0x88}
};
static TEEC_Context g_context;
static TEEC_Session g_session;

static TEEC_Result TeecInit(void)
{
    TEEC_Operation opt = {0};
    TEEC_Result ret = TEEC_SUCCESS;
    uint32_t origin = 0;

    ret = TEEC_InitializeContext(NULL, &g_context);
    if (ret != TEEC_SUCCESS) {
        TEEC_Error("Teec initial context failed.\n");
        return ret;
    }

    opt.started = 1;
    opt.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    g_context.ta_path = (uint8_t *)TA_PATH;
    ret = TEEC_OpenSession(&g_context, &g_session, &TA_uuid, TEEC_LOGIN_IDENTIFY, NULL, &opt, &origin);
    if (ret != TEEC_SUCCESS) {
        TEEC_Error("Teec open session failed. result: %x origin: %d.\n", (int)ret, origin);
        TEEC_FinalizeContext(&g_context);
    }

    return ret;
}

static TEEC_Result TeecClose(void)
{
    TEEC_CloseSession(&g_session);
    TEEC_FinalizeContext(&g_context);
}

static TEEC_Result CmdGetMemInfo(MemInfo *mem)
{
    TEEC_Operation opt = {0};
    TEEC_Result ret = TEEC_SUCCESS;
    uint32_t origin = 0;
    uint64_t memValArr[MEM_INFO_COUNT] = {0};

    opt.started = 1;
    opt.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_OUTPUT);
    opt.params[0].tmpref.buffer = memValArr;
    opt.params[0].tmpref.size = MEM_INFO_COUNT * sizeof(uint64_t);
    ret = TEEC_InvokeCommand(&g_session, CMD_GET_MEMORY, &opt, &origin);
    if (ret != TEEC_SUCCESS) {
        TEEC_Error("Teec get memory failed. result: %x origin: %d.\n", (int)ret, origin);
    } else {
        mem->totalMem = (memValArr[0] * opt.params[3].value.a) / K_BYTES;
        mem->freeMem = (memValArr[1] * opt.params[3].value.a) / K_BYTES;
    }

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
        TEEC_Error("Total Memory is less than reserve memory\n");
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