#include "tee_client_api.h"

#define OPERATION_START_FLAG 1
#define MAX_STR_LEN 200 //now set randomly
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3
#define SIGEND_PUBKEY_BUF 1000 //now set randomly
#define TEE_PUBKEY_BUF 500 //now set randomly
#define KCM_ENCRYPT_BUF 600 //now set randomly
#define KMS_PUBKEY_BUF 800 //now set randomly

static const TEEC_UUID Uuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};

enum {
    CMD_KTA_INITIALIZE      = 0x00000001, //send request to kta for setup snd initialization, get parameters kta generated during initialization
    CMD_KTA_INITREPLY       = 0x00000002, //send reply to kta for initialization
    CMD_GET_REQUEST         = 0x00000003, //ask kta for commands in its cmdqueue, and send ta identification whose trusted status needs to update
    CMD_RESPOND_REQUEST     = 0x00000004, //reply a command to kta(maybe one)
};

typedef struct _tagCmdNode{
    int32_t cmd;
    TEEC_UUID    taId;
    TEEC_UUID    keyId;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;  // -1: empty; 0~MAX_TA_NUM: next cmd for search operation.
} CmdNode;

TEEC_Context context = {0};
TEEC_Session session = {0};

//这个函数实现的内容可以放在主函数内
TEEC_Context initcontext(TEEC_Context context) {
    context.ta_path = "/root/data/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec"; //to be set, the path of kta mirror
    return context;
}

TEEC_Result initialize(TEEC_Context *context, TEEC_Session *session){
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result ret;
    TEEC_Value initresult = {0};

    char ktaSignedPubkey[SIGEND_PUBKEY_BUF] = {0};
    char teePubkey[TEE_PUBKEY_BUF] = {0};
    char kcmEncryptKey[KCM_ENCRYPT_BUF] = {0};
    char kmsPubKey[KMS_PUBKEY_BUF] = {0};
    unsigned int pubkeyBufLen = SIGEND_PUBKEY_BUF;
    unsigned int teePubkeyBufLen = TEE_PUBKEY_BUF;
    unsigned int kcmKeyBufLen = KCM_ENCRYPT_BUF;
    unsigned int kmsPubkeyBufLen = KMS_PUBKEY_BUF;

    ret = TEEC_InitializeContext(NULL, context);
    if (ret != TEEC_SUCCESS) {
        printf("teec initial failed");
        return 0;
    }

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    ret = TEEC_OpenSession(context, session, &Uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("teec open session failed");
        TEEC_FinalizeContext(context);
        return 0;
    }

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT, //存放初始化结果，具体有待商议
        TEEC_MEMREF_TEMP_OUTPUT, //本来是存放TEE证书私钥签名的KTA公钥，现在待定
        TEEC_MEMREF_TEMP_OUTPUT, //本来是存放TEE设备公钥，现在待定
        TEEC_NONE
    );
    operation.params[PARAMETER_FRIST].value = initresult;
    operation.params[PARAMETER_SECOND].tmpref.buffer = ktaSignedPubkey;
    operation.params[PARAMETER_SECOND].tmpref.size = pubkeyBufLen;
    operation.params[PARAMETER_THIRD].tmpref.buffer = teePubkey;
    operation.params[PARAMETER_THIRD].tmpref.size = teePubkeyBufLen;

    ret = TEEC_InvokeCommand(session, CMD_KTA_INITIALIZE, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("kta initialize failed, codes=0x%x, origin=0x%x", ret, origin);
        return ret;
    } else if (initresult.a != 0x01) {
        /* 到kta初始化失败处理逻辑 */
    }
    
    /* 对TEE证书私钥签名的KTA公钥和TEE设备公钥进行处理 */

    //当kcm返回处理结果
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES( //是不是也需要像上面用一个标志位？
        TEEC_MEMREF_TEMP_OUTPUT, //存放KCM生成的加密密钥
        TEEC_MEMREF_TEMP_OUTPUT, //存放KMS公钥
        TEEC_NONE,
        TEEC_NONE
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = kcmEncryptKey; //已经赋值的缓冲区，下同
    operation.params[PARAMETER_FRIST].tmpref.size = kcmKeyBufLen;
    operation.params[PARAMETER_SECOND].tmpref.buffer = kmsPubKey;
    operation.params[PARAMETER_SECOND].tmpref.size = kmsPubkeyBufLen;
    ret = TEEC_InvokeCommand(&session, CMD_KTA_INITREPLY, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("kta initialize reply failed, codes=0x%x, origin=0x%x", ret, origin);
        return ret;
    }
    return TEEC_SUCCESS;
}

//during one heartbeat
/*
    cmdnum = 1;
    while(cmdnum != 0)) {
*/
TEEC_Result get_request(TEEC_Session *session) {
    TEEC_Operation operation = {0};
    TEEC_Value requestnum = {0};
    uint32_t origin = 1;
    TEEC_Result ret;
    CmdNode *cmdbuffer;
    void *talist; //to be set
    void *tatrusted;

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT, //存放一个TA请求
        TEEC_VALUE_OUTPUT, //存放请求队列中还有多少请求
        TEEC_MEMREF_TEMP_INPUT, //存放需要更新可信状态的TAuuid列表
        TEEC_MEMREF_TEMP_OUTPUT //存放需要更新可信状态的TA可信状态查询结果
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = cmdbuffer;
    operation.params[PARAMETER_FRIST].tmpref.size = sizeof(CmdNode);
    operation.params[PARAMETER_SECOND].value = requestnum;
    operation.params[PARAMETER_THIRD].tmpref.buffer = talist;
    operation.params[PARAMETER_THIRD].tmpref.size = 100;
    operation.params[PARAMETER_FOURTH].tmpref.buffer = tatrusted;
    operation.params[PARAMETER_FOURTH].tmpref.size = 100;
    ret = TEEC_InvokeCommand(session, CMD_GET_REQUEST, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("get kta requests failed, codes=0x%x, origin=0x%x", ret, origin);
        return ret;
    }
    if (requestnum.a == 0) /*break*/;
    /*
    cmdnum = requestnum.a
    */
    return TEEC_SUCCESS;
}

    // handle ta's request
    // update ta's trusted status

TEEC_Result send_reply(TEEC_Session *session, uint32_t number) {
    TEEC_Operation operation = {0};
    TEEC_Value requestnum = {0}; //请求返回的数量应该已经确定好了
    uint32_t origin = 2;
    TEEC_Result ret;
    char retbuffer[number]; //一次返回多少请求，数据结构有待商定

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, //存放TA请求返回列表
        TEEC_VALUE_INPUT, //存放一次返回多少请求
        TEEC_NONE,
        TEEC_NONE
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = retbuffer;
    operation.params[PARAMETER_FRIST].tmpref.size = number * sizeof(char);
    operation.params[PARAMETER_SECOND].value = requestnum;
    ret = TEEC_InvokeCommand(session, CMD_RESPOND_REQUEST, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("respond kta requests failed, codes=0x%x, origin=0x%x", ret, origin);
        return ret;
    }
    return TEEC_SUCCESS;
}
/*}
*/

void shutdownkta(TEEC_Context *context, TEEC_Session *session) {
    TEEC_CloseSession(session);
    TEEC_FinalizeContext(context);
}