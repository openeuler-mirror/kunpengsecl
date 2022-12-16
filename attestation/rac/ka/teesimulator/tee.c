#include "tee.h"
bool getDataFromFile(char *filename,uint8_t *data,uint32_t size);
enum {
    CMD_KTA_INITIALIZE      = 0x00000001, //send request to kta for setup snd initialization, get parameters kta generated during initialization
    CMD_KTA_INITREPLY       = 0x00000002, //send reply to kta for initialization
    CMD_GET_REQUEST         = 0x00000003, //ask kta for commands in its cmdqueue, and send ta identification whose trusted status needs to update
    CMD_RESPOND_REQUEST     = 0x00000004, //reply a command to kta(maybe one)
};
//simulator
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    context->ta_path = "/root/data/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec";
    printf("success\n");
    return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
    if (sizeof(context)==0){
        printf("Finalize the context is failed!\n");
    }
    printf("Finalize the context is successed!\n");
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
    const TEEC_UUID *destination, uint32_t connectionMethod,
    const void *connectionData, TEEC_Operation *operation,
    uint32_t *returnOrigin)
{
    if(sizeof(context)==0||session==NULL||connectionMethod==NULL||operation==NULL){
        printf("OpenSession is null\n");
    }
    return TEEC_SUCCESS;
}

void TEEC_CloseSession(TEEC_Session *session)
{
    if(session==NULL){
        printf("CloseSession is null\n");
    }
    printf("Close the session is successed!\n");
}
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin)
{
    // if(session==NULL||operation==NULL){
    //     printf("InvokeCommand is null\n");
    // }
    uint32_t size = sizeof(operation->params[PARAMETER_SECOND].tmpref.size);
    uint8_t *test = (uint8_t *)malloc(sizeof(uint8_t) * size);
    switch (commandID)
    {
    case CMD_KTA_INITIALIZE:
        /*
            初始化阶段：外部ka向kta发送kcm的公钥
            kta向ka返回自己的公钥证书
            假设：operation的第一个字段为KCM的公钥，第二个字段存放返回的KTA公钥证书
        */
       //对kcm的公钥证书进行一个简单的验证
       if(operation->params[PARAMETER_FRIST].tmpref.buffer==NULL||operation->params[PARAMETER_FRIST].tmpref.size==NULL){
            TEEC_Error("invokeCommandFn is null!\n");
            return TEEC_ERROR_GENERIC;
       }
       //获取kta的公钥证书并返回
        getDataFromFile("../cert/kta.crt",operation->params[PARAMETER_SECOND].tmpref.buffer,size);
        printf("get kta initialize command\n");
        printf("buffer size: %d\n",operation->params[PARAMETER_SECOND].tmpref.size);
        break;
    case CMD_KTA_INITREPLY:
        printf("put kta initialize reply\n");
        break;
    default:
        break;
    }
}
bool getDataFromFile(char *filename,uint8_t *data,uint32_t size)
{   
    FILE *f = fopen(filename,"rb");
        if (!f)
   {
      fprintf(stderr, "unable to open: %s\n", "file");
      return false;
   }
   fwrite(data, sizeof(char),size , f);
   fclose(f);
   return true;
}
//Test
static const TEEC_UUID Uuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};
TEEC_Context *context = {0};
TEEC_Session *session = {0};
int main(){
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
        TEEC_MEMREF_TEMP_INPUT,   //存放KCM公钥
        TEEC_MEMREF_TEMP_INPUT,   //存放KTA公钥证书
        TEEC_MEMREF_TEMP_INPUT,   //存放KTA私钥
        TEEC_MEMREF_TEMP_OUTPUT  //存放KTA公钥证书（返回）
    );
    operation.params[PARAMETER_FRIST].tmpref.buffer = ktaSignedPubkey;
    operation.params[PARAMETER_FRIST].tmpref.size = pubkeyBufLen;
    operation.params[PARAMETER_SECOND].tmpref.buffer = teePubkey;
    operation.params[PARAMETER_SECOND].tmpref.size = teePubkeyBufLen;
    getDataFromFile("../cert/ca.crt",operation.params[PARAMETER_FRIST].tmpref.buffer,operation.params[PARAMETER_FRIST].tmpref.size);
    ret = TEEC_InvokeCommand(session, CMD_KTA_INITIALIZE, &operation, &origin);
    if (ret != TEEC_SUCCESS) {
        printf("kta initialize failed, codes=0x%x, origin=0x%x", ret, origin);
        return ret;
    } else if (initresult.a != 0x01) {
        /* 到kta初始化失败处理逻辑 */
    }
    return 0;
}