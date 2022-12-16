#include "ktalib.h"

#define OPERATION_START_FLAG 1
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3
static const TEEC_UUID Uuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};
enum TEEC_Return{
    TEEC_ERROR_BAD_BUFFER_DATA = 0xFFFF0006
};
enum{
    INITIAL_CMD_NUM = 0x7FFFFFFF
};
enum {
    CMD_KTA_INITIALIZE      = 0x00000001, //send request to kta for setup snd initialization, get parameters kta generated during initialization
    CMD_GET_REQUEST         = 0x00000002, //ask kta for commands in its cmdqueue, and send ta identification whose trusted status needs to update
    CMD_RESPOND_REQUEST     = 0x00000003, //reply a command to kta(maybe one)
    CMD_CLOSE_KTA           = 0x00000004,
};

TEEC_Context context = {0};
TEEC_Session session = {0};

/*编译方法
    gcc -fPIC -shared -o libkta.so ktalib.c ./itrustee_sdk/src/CA/libteec_adaptor.c -I ./itrustee_sdk/include/CA/
*/

// 初始化上下文和会话
TEEC_Result InitContextSession(uint8_t* ktapath) {
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result ret;

    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    context.ta_path = ktapath;
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE);

    ret = TEEC_OpenSession(&context, &session, &Uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        return ret;
    }
    return ret;
}

// 向KTA发出初始化命令
TEEC_Result KTAinitialize(struct buffer_data* kcmPubKey, struct buffer_data* ktaPubCert, struct buffer_data* ktaPrivKey, struct buffer_data *out_data){
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result ret;

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT,   //存放KCM公钥
        TEEC_MEMREF_TEMP_INPUT,   //存放KTA公钥证书
        TEEC_MEMREF_TEMP_INPUT,   //存放KTA私钥
        TEEC_MEMREF_TEMP_OUTPUT  //存放KTA公钥证书（返回）
    );

    operation.params[PARAMETER_FRIST].tmpref.buffer = kcmPubKey->buf;
    operation.params[PARAMETER_FRIST].tmpref.size = kcmPubKey->size;
    operation.params[PARAMETER_SECOND].tmpref.buffer = ktaPubCert->buf;
    operation.params[PARAMETER_SECOND].tmpref.size = ktaPubCert->size;
    operation.params[PARAMETER_THIRD].tmpref.buffer = ktaPrivKey->buf;
    operation.params[PARAMETER_THIRD].tmpref.size = ktaPrivKey->size;
    operation.params[PARAMETER_FOURTH].tmpref.buffer = out_data->buf;
    operation.params[PARAMETER_FOURTH].tmpref.size = out_data->size;

    ret = TEEC_InvokeCommand(&session, CMD_KTA_INITIALIZE, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }

    return TEEC_SUCCESS;
}
// 从KTA拿取密钥请求
TEEC_Result KTAgetCommand(struct buffer_data* out_data, uint32_t* retnum){
    TEEC_Operation operation = {0};
    TEEC_Value cmdnum = {0};
    uint32_t origin = 0;
    TEEC_Result ret;
    cmdnum.a = INITIAL_CMD_NUM;
    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_OUTPUT, //存放请求
        TEEC_VALUE_OUTPUT, //存放剩余请求数量(包含此次得到的的请求在内)
        TEEC_NONE,
        TEEC_NONE
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = out_data->buf;
    operation.params[PARAMETER_FRIST].tmpref.size = out_data->size;
    operation.params[PARAMETER_SECOND].value = cmdnum;
    ret = TEEC_InvokeCommand(&session, CMD_GET_REQUEST, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    *retnum = cmdnum.a;
    return TEEC_SUCCESS;
}

// 向KTA返回密钥请求结果
TEEC_Result KTAsendCommandreply(struct buffer_data* in_data){
    TEEC_Operation operation = {0};
    TEEC_Value ktares = {0};
    uint32_t origin = 0;
    TEEC_Result ret;

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, //存放请求结果
        TEEC_VALUE_OUTPUT, //存放KTA处理结果
        TEEC_NONE,
        TEEC_NONE
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = in_data->buf;
    operation.params[PARAMETER_FRIST].tmpref.size = in_data->size;
    operation.params[PARAMETER_SECOND].value = ktares;
    ret = TEEC_InvokeCommand(&session, CMD_RESPOND_REQUEST, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    if (ktares.a == 0){
        return TEEC_ERROR_BAD_BUFFER_DATA;
    }
    return TEEC_SUCCESS;
}

// 关闭与KTA的连接
void KTAshutdown() {
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

// 终止kta, 测试用
TEEC_Result KTAterminate(){
    TEEC_Operation operation = {0};
    uint32_t origin = 0;
    TEEC_Result ret;

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, 
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );
    ret = TEEC_InvokeCommand(&session, CMD_CLOSE_KTA, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        return ret;
    }
    return TEEC_SUCCESS;
}