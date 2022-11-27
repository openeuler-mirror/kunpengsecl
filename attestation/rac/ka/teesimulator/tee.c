#include "tee.h"
enum {
    CMD_KTA_INITIALIZE      = 0x00000001, //send request to kta for setup snd initialization, get parameters kta generated during initialization
    CMD_KTA_INITREPLY       = 0x00000002, //send reply to kta for initialization
    CMD_GET_REQUEST         = 0x00000003, //ask kta for commands in its cmdqueue, and send ta identification whose trusted status needs to update
    CMD_RESPOND_REQUEST     = 0x00000004, //reply a command to kta(maybe one)
};
//simulator
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
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
    if(session==NULL||operation==NULL){
        printf("InvokeCommand is null\n");
    }
    switch (commandID)
    {
    case CMD_KTA_INITIALIZE:
        printf("get kta initialize command\n");

        break;
    case CMD_KTA_INITREPLY:
        printf("put kta initialize reply\n");
        break;
    default:
        break;
    }
}