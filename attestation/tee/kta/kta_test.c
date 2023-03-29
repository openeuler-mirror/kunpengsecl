#include "kta_command.h"
#include "kta_common.h"
#include <tee_log.h>
#include <tee_defines.h>
#include <securec.h>
#include <tee_mem_mgmt_api.h>
#include <tee_core_api.h>
#include "tee_trusted_storage_api.h"

#define OPERATION_START_FLAG 1
#define PARAM_COUNT 4
#define STRLENGTH 900
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3

#define VALUE_INIT 0x7fffffff
#define TIMEOUT 0x00000BB8

enum{
    INITIAL_CMD_NUM = 0x7FFFFFFF
};

enum {
    CMD_KEY_GENERATE        = 0x70000001,
    CMD_KEY_SEARCH          = 0x70000002,
    CMD_KEY_DELETE          = 0x70000003,
    CMD_KCM_REPLY           = 0x70000004,
    CMD_CLEAR_CACHE         = 0x70000005
};

void *keyid_storage_path = "sec_storage_data/takeyid.txt";
//static const uint32_t session_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
//        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
char teststr[] = "{\"Key\":\"01d84451e832dcdb4fca4f0bdc1c1c97d86d6be9d2ae3995057221c28651dd940ae149acd11ad1c466b648f2623d76b14c5e497f06c85cc8694ddd5aa15411ff2eac48d41e619d5655b89c6b97894c9071dc1b358823c037f9cfd54a12700a96354572bbcc27f397d2bed9549530eabe78d4d1d473c943e4d7b7d416b714726b724197ec918efcd77bd087a2bdc3e828ad747c90f216dbc3dc785d3d17c3800e7194500b9e900f259ffc830d6757d35f345c6abdb91e0b23c192c29c19c227752d76523fe039afe2ff862dccccac3b649985cd9785319638a8fb20f64745221900b079fe6e28e60780de341d297176561099a9c79ed3a520115e82a14eb61827\",\"EncCmdData\":\"147ac3138d017aedfaf4773694ea23e4e08b319a9e57249577299bbbaa28b907407ad6c3cdbbb2e14da91f9a425e4c0daba0d8eb0ba4d793386521600432b6345a6216d1d9501783c34cdad9e6b10fd12598882aad86cb0a5a877f76a138de9c638dda608b754527e996fbf8ea59c5ef2e9f131725f0391cfe4610735151f42cfc8322dff6efab36321e172c473c9aa8bbaee0becf8d426043e608ad0e33bd83f870bb2f6a22031dfe3c11bf85eedf3c620484a08b\"}";

void chartouuid(TEE_UUID *uuid, int8_t charuuid[37]) {
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

void TestKTAInitialize(){
    uint32_t param_type = 0;
    TEE_Param params[PARAM_COUNT];
    TEE_Result ret;
    tlogd("testing KTAInitialize with empty value-------------");
    ret = KTAInitialize(param_type, params);
    if(ret == TEE_SUCCESS) {
        tlogd("Test KTAInitialize with empty value failed");
    } else {
        tlogd("Test KTAInitialize with empty value succeeded");
    }
}

void TestSendRequest(){
    uint32_t param_type = 0;
    TEE_Param params[PARAM_COUNT];
    TEE_Result ret;
    tlogd("testing SendRequest with empty value---------------");
    ret = SendRequest(param_type, params);
    if(ret == TEE_SUCCESS) {
        tlogd("Test SendRequest with empty value failed");
    } else {
        tlogd("Test SendRequest with empty value succeeded");
    }
    tlogd("testing SendRequest with right value");
    param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
        );
    params[PARAMETER_FRIST].memref.buffer = (char*)malloc(2048*sizeof(char));
    params[PARAMETER_FRIST].memref.size = 2048;
    params[PARAMETER_SECOND].value.a = INITIAL_CMD_NUM;
    params[PARAMETER_SECOND].value.b = INITIAL_CMD_NUM;
    ret = SendRequest(param_type, params);
    if(ret == TEE_SUCCESS) {
        tlogd("Test SendRequest with right value succeeded");
    } else {
        tlogd("Test SendRequest with right value failed");
    }
}

void TestGetResponse(){
    uint32_t param_type = 0;
    TEE_Param params[PARAM_COUNT];
    TEE_Result ret;
    tlogd("testing GetResponse with empty value----------------");
    ret = GetResponse(param_type, params);
    if(ret == TEE_SUCCESS) {
        tlogd("Test GetResponse with empty value failed");
    } else {
        tlogd("Test GetResponse with empty value succeeded");
    }
    tlogd("testing GetResponse with right value");
    param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
        );
    params[PARAMETER_FRIST].memref.buffer = teststr;
    params[PARAMETER_FRIST].memref.size = STRLENGTH;
    params[PARAMETER_SECOND].value.a = INITIAL_CMD_NUM;
    tlogd("testing GetResponse with right value----------------");
    ret = GetResponse(param_type, params);
    if(ret == TEE_SUCCESS) {
        tlogd("Test GetResponse with right value succeeded");
    } else {
        tlogd("Test GetResponse with right value failed");
    }
}

void TestReset_All(){
    tlogd("testing Reset_All ----------------------------------");
    TEE_Result ret; 
    ret = ResetAll();
    if(ret != TEE_SUCCESS) {
        tlogd("Test Reset_All failed");
    } else {
        tlogd("Test Reset_All succeeded");
    }
    tlogd("testing Reset_All for a second time");
    ret = ResetAll();
    if(ret == TEE_SUCCESS) {
        tlogd("Test Reset_All for a second time failed");
    } else {
        tlogd("Test Reset_All for a second time succeeded");
    }
}

void test_main(){
    tlogd("running test_main---------------------------------");
    TestKTAInitialize();
    TestSendRequest();
    TestGetResponse();
    TestReset_All();
    tlogd("test_main ends------------------------------------");
}
