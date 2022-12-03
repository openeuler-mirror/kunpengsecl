/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: leezhenxiang
Create: 2022-11-04
Description: key managing module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
    2. 2022-12-01   waterh2o
        Implementation function sendrequest and getresponse
*/

#include <tee_defines.h>
#include <kta_common.h>
#include <tee_crypto_api.h>
//#include <cJSON.h>

#define PARAM_COUNT 4

// ===================Communication with kcm====================================

//--------------------------1、SendRequest---------------------------------------------

TEE_Result SendRequest(uint32_t param_type, TEE_Param params[PARAM_COUNT], CmdQueue *cmdQueue) {
    //todo: send request to ka when ka polls, and answer ta trusted state which ka asks
    TEE_Result ret;
    int queue_empty;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //Judge whether cmd queue is empty 
    queue_empty = isQueueEmpty(cmdQueue);
    if (!queue_empty){
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    //generater Request Return value for ka
    CmdRequest finalrequest;
    generaterFinalRequest(finalrequest);
    params[0].memref.buffer = ;
    return TEE_SUCCESS;
}
int isQueueEmpty(CmdQueue *cmdQueue){
    // 1=empty,0=not empty
    if (cmdQueue->head == -1 && cmdQueue->tail == -1){
        tloge("cmdQueue is empty,nothing should be sent.\n");
        return 1;
    }
    return 0;
}


//generate Data encryption symmetric key kcm-pub key
TEE_Result generaterCmdDataKey(CmdRequest *intermediateRequest){
};


void encryption(char *pubkeyname, CmdRequest *intermediateRequest,
                CmdRequest *finalrequest){
    /*
    todo:
    1 encrypt cmd_data by symmetric key
    2 encrypt symmetric key by kcm-pub key
    */
   
};

int dequeue(CmdQueue *cmdQueue){
    //1=failed ;0=success
    int rtn;
    rtn = isQueueEmpty(cmdQueue);
    if (rtn){
        return rtn;
    }
    int cmd_now = cmdQueue->head;
    if (cmdQueue->queue[cmd_now].next = -1){
        cmdQueue->tail = -1;
    }
    cmdQueue->head = cmdQueue->queue[cmd_now].next;
    cmdQueue->queue[cmd_now].next = -1;
    return 0;
};

void generaterFinalRequest(){
    /* get request data from cmdqueue,and generate final request*/
    //申请IntermediateRequest临时内存
    TEE_AllocateTransientObject();
    generaterCmdDataKey();
    json();//cmdQueue.queue[cmdQueue.head]
    encryption();
    json();
    //释放IntermediateRequest
    return;
}

//--------------------------2、GetResponse---------------------------------------------

TEE_Result GetResponse(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    //todo: Get Response from ka when kta had sent request to kcm before
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    decryption();
    parsejson();
    switch(cmd);//saveinfo?savetakey?
    //put it to cmd
}

void decryption(){
    /*
    todo:
    1 decrypt symmetric key by kta-priv key
    2 decrypt cmd_data by symmetric key
    */
};


void saveTaInfo(TEE_UUID TA_uuid, char *account, char *password) {
    /*
    todo: options to save ta info in cache,insert the info to cache.ta[?]
    1、search for empty tainfo-node(in empty ta info,head and tail = -1)
    2、save the info in the empty node
    3、modify head next tail etc...
    */

}

void saveTaKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue) {
    //todo: options to save a certain key in cache, Same as the above example
}

// ===================Communication with kcm from ta====================================

void generateKcmRequest(){
    /* when kta can't complete ta-operation in local kta,
    generate a request and insert it in cmdqueue*/
}


// ===================Communication with ta=============================================

//---------------------------InitTAKey--------------------------------------------------

TEE_Result GenerateTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT],Cache *cache,CmdQueue *cmdqueue) {
    //TEE_UUID TA_uuid, TEE_UUID masterkey, char *account, char *password
    //todo: new a key for ta
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  
        TEE_PARAM_TYPE_VALUE_OUTPUT )) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
    //params[2]值固定为1
    generatKcmRequest(); //生成请求成功或失败的结果存放到params[3]的值中
}
//---------------------------SearchTAKey------------------------------------------------

TEE_Result SearchTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT],Cache *cache,CmdQueue *cmdqueue) {
    //todo: search a certain ta key, if not exist, call generateKcmRequest(）to generate SearchTAKey request
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  
        TEE_PARAM_TYPE_VALUE_OUTPUT )) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
}

//---------------------------DeleteTAKey------------------------------------------------

TEE_Result DeleteTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT],Cache *cache) {
    //todo: delete a certain key in the cache
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  
        TEE_PARAM_TYPE_NONE )) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
}

//----------------------------DestoryKey------------------------------------------------

TEE_Result DestoryKey(uint32_t param_type, TEE_Param params[PARAM_COUNT],Cache *cache,CmdQueue *cmdqueue) {
    //todo: delete a certain key by calling DeleteTAKey(), then generate a delete key request in TaCache
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  
        TEE_PARAM_TYPE_VALUE_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
}

//----------------------------GetKcmReply------------------------------------------------

TEE_Result GetKcmReply(uint32_t param_type, TEE_Param params[PARAM_COUNT], CmdQueue *replyqueue){
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,  
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
}

//----------------------------ClearCache------------------------------------------------

TEE_Result ClearCache(uint32_t param_type, TEE_Param params[PARAM_COUNT], Cache *cache) {
    //todo: clear all ta cache
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,  
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //params[0].memref.buffer内为输入的cmd结构体
}