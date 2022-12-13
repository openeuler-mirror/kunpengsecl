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
#include <tee_object_api.h>
#include <tee_crypto_api.h>
#include <securec.h>
#include <kta_common.h>
//#include <cJSON.h>

#define PARAM_COUNT 4

extern Cache cache;
extern CmdQueue cmdqueue;
extern ReplyCache replycache;
// ===================Communication with kcm====================================

//--------------------------1、SendRequest---------------------------------------------
bool isQueueEmpty(){
    // 1=empty,0=not empty
    if (cmdqueue.head == cmdqueue.tail){
        tlogd("cmdqueue is empty,nothing should be sent.\n");
        return true;
    }
    return false;
}

void dequeue(CmdNode *cmdnode){
    cmdnode = &cmdqueue.queue[cmdqueue.head];
    cmdqueue.head = (cmdqueue.head + 1) % MAX_QUEUE_SIZE;
};

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

void generaterFinalRequest(CmdNode cmdnode, CmdRequest *request){
    /* get request data from cmdqueue,and generate final request*/
    //申请IntermediateRequest临时内存
    TEE_AllocateTransientObject();
    generaterCmdDataKey();
    json();//cmdqueue.queue[cmdqueue.head]
    encryption();
    json();
    //释放IntermediateRequest
    return;
}

TEE_Result SendRequest(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    CmdNode curNode;
    CmdRequest finalrequest;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL ||
        params[0].memref.size < sizeof(CmdRequest)) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //Judge whether cmd queue is empty 
    if (isQueueEmpty()){
        params[1].value.a = 0;
        tlogd("cmd queue is empty");
        return TEE_SUCCESS;
    }
    //if is not empty, dequeue a request from the queue
    params[1].value.a = (cmdqueue.tail + MAX_QUEUE_SIZE - cmdqueue.head) % MAX_QUEUE_SIZE;
    dequeue(&curNode);

    //generater Request Return value for ka
    generaterFinalRequest(curNode, &finalrequest);
    memcpy_s(params[0].memref.buffer, sizeof(finalrequest), &finalrequest, sizeof(finalrequest));
    return TEE_SUCCESS;
}

//--------------------------2、GetResponse---------------------------------------------

void decryption(){
    /*
    todo:
    1 decrypt symmetric key by kta-priv key
    2 decrypt cmd_data by symmetric key
    */
}

void parsejson(){

}

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

void saveReplyCache() {
    //todo: save a reply in replycache
}

TEE_Result GetResponse(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
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
    switch(cmd) {
    case saveinfo:
        saveTaInfo();
    case generate_reply:
        saveTaKey();
        saveReplyCache();
    case search_reply:
        saveTaKey();
    case delete_key:
        saveReplyCache();
    }

}

// ===================Communication with kcm from ta====================================

bool generateKcmRequest(TEE_Param params[PARAM_COUNT]){
    /* when kta can't complete ta-operation in local kta,
    generate a request and insert it in cmdqueue*/
    // 若队列已满，则无法添加新命令
    if (cmdqueue.head == cmdqueue.tail + 1) {
        tloge("cmd queue is already full");
        return false;
    }
    CmdNode *n = params[0].memref.buffer;
    cmdqueue.queue[cmdqueue.tail] = *n;
    cmdqueue.tail = (cmdqueue.tail + 1) % MAX_TA_NUM;
    return true;
}


// ===================Communication with ta=============================================

//---------------------------InitTAKey--------------------------------------------------

TEE_Result GenerateTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
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
    bool res = generateKcmRequest(params); //生成请求成功或失败的结果存放到params[3]的值中
    if (res) {
        params[3].value.b = 1;
        return TEE_SUCCESS;
    }
    params[3].value.b = 0;
    return TEE_ERROR_OVERFLOW;
}
//---------------------------SearchTAKey------------------------------------------------

void flushCache(TEE_UUID taid, TEE_UUID keyid) {
    /*
    flush the cache according to the LRU algorithm
    support two types of element refresh:
    1.ta sequence;
    2.key sequence;
    */
    int32_t head = cache.head;
    if (!CheckUUID(cache.ta[head].id, taid)) {
        int32_t cur = head;
        int32_t nxt = cache.ta[cur].next;
        while (nxt != -1) {
            if (CheckUUID(cache.ta[nxt].id, taid)) {
                cache.ta[cur].next = cache.ta[nxt].next;
                cache.ta[nxt].next = head;
                cache.head = nxt;
                break;
            }
            cur = nxt;
            nxt = cache.ta[nxt].next;
        }
    }
    TaInfo ta = cache.ta[head];
    head = ta.head;
    if (!CheckUUID(ta.key[head].id, keyid)) {
        int32_t cur = head;
        int32_t nxt = ta.key[cur].next;
        while (nxt != -1) {
            if (CheckUUID(ta.key[nxt].id, keyid)) {
                ta.key[cur].next = ta.key[nxt].next;
                ta.key[nxt].next = head;
                ta.head = nxt;
                break;
            }
            cur = nxt;
            nxt = ta.key[nxt].next;
        }
    }
}

TEE_Result SearchTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
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
    CmdNode *n = params[0].memref.buffer;
    int32_t cur = cache.head;
    while (cur != -1) {
        if (CheckUUID(cache.ta[cur].id, n->taId)) {
            TaInfo ta = cache.ta[cur];
            int32_t idx = ta.head;
            while (idx != -1) {
                if (CheckUUID(ta.key[idx].id, n->keyId)) {
                    params[1].memref.size = sizeof(ta.key[idx].value);
                    params[1].memref.buffer = ta.key[idx].value;
                    params[2].value.a = 0;
                    // 更新cache
                    flushCache(n->taId, n->keyId);
                    return TEE_SUCCESS;
                }
                idx = ta.key[idx].next;
            }
        }
        cur = cache.ta[cur].next;
    }
    params[2].value.a = 1;
    bool res = generateKcmRequest(params);
    if (res) {
        params[3].value.b = 1;
        return TEE_SUCCESS;
    }
    params[3].value.b = 0;
    return TEE_ERROR_OVERFLOW;
}

//----------------------------DestoryKey------------------------------------------------

TEE_Result DestoryKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
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

    TaInfo regTa;
    int32_t taIndex;
    int32_t targetTaIndex;
    int32_t keyIndex;
    int32_t targetKeyIndex;
    CmdNode *n = params[0].memref.buffer;

    //先对TA进行本地证明，证明通过之后根据UUID和密钥ID查询密钥，然后验证TA的账号密码，验证通过后删除指定密钥，最后向KCM发送删除指定密钥的请求

    //TODO:local verification of TA
    //kta通过ka到ras中获取指定ta基准值，在kta中调用本地证明接口获取ta度量报告，然后在kta中进行验证
    //暂定:比较CmdNode和Cache的UUID和账号密码
    //TODO:verify account and password of TA
    if(!verifyTApasswd(n->taId, n->account, n->password)){                  // def of verifyTApasswd() is in ta_authentiate.c
        tloge("verify Ta password failed");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    taIndex = cache.head;
    while (taIndex != END_NULL && !CheckUUID(n->taId,cache.ta[taIndex].id)) // def of CheckUUID() is in ta_authentiate.c
    {
        //loop
        taIndex = cache.ta[taIndex].next; //move to next one
    }
    targetTaIndex = taIndex;

    //TODO:search key on the basis of UUID and key id   (in Cache.TaInfo)
    regTa = cache.ta[targetTaIndex];
    keyIndex = regTa.head;
    while (keyIndex != END_NULL && !CheckUUID(n->keyId ,regTa.key[keyIndex].id))
    {
        //loop
        keyIndex = regTa.key[keyIndex].next; //move to next one
    }
    if(keyIndex == END_NULL){
        tloge("target key not found");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    targetKeyIndex = keyIndex;

    //TODO:delete certain key                           (in Cache.TaInfo)
    if(regTa.head == targetKeyIndex){
        regTa.head = regTa.key[targetKeyIndex].next;
    }
    else{
        keyIndex = regTa.head;
        while (regTa.key[keyIndex].next != targetKeyIndex){
            //loop
            keyIndex = regTa.key[keyIndex].next; //move to next one
        }
        int32_t nextIndex = regTa.key[targetKeyIndex].next;
        regTa.key[keyIndex].next = nextIndex;
        if(nextIndex == END_NULL){
            regTa.tail = keyIndex;
        }
    }
    cache.ta[targetTaIndex] = regTa;

    //TODO:send request of delete key to KCMS
    bool res = generateKcmRequest(params); //生成请求成功或失败的结果存放到params[3]的值中
    if (res) {
        params[3].value.b = 1;
        return TEE_SUCCESS;
    }
    params[3].value.b = 0;
    return TEE_ERROR_OVERFLOW;
}

//----------------------------GetKcmReply------------------------------------------------

TEE_Result GetKcmReply(uint32_t param_type, TEE_Param params[PARAM_COUNT]){
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,  
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,  
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    CmdNode *n = params[0].memref.buffer;
    if (!verifyTApasswd(n->taId, n->account, n->password)) {
        params[1].value.b = 0;
        return TEE_ERROR_ACCESS_DENIED;
    }
    //params[0].memref.buffer内为输入的cmd结构体
    if (replycache.head == -1 && replycache.tail == -1) {
        tloge("get kcm reply error: reply cache is empty\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    int32_t cur = replycache.head;
    int32_t pre = -2;
    while (cur != -1) {
        if (CheckUUID(replycache.list[cur].taId, n->taId)) {
            params[1].memref.size = sizeof(ReplyNode);
            params[1].memref.buffer = &replycache.list[cur];
            if (pre == -2) {
                replycache.head = replycache.list[cur].next;
            } else {
                replycache.list[pre].next = replycache.list[cur].next;
            }
            return TEE_SUCCESS;
        }
        pre = cur;
        cur = replycache.list[cur].next;
    }
    tloge("get kcm reply error: reply to ta is not found");
    return TEE_ERROR_ITEM_NOT_FOUND;
}

//----------------------------ClearCache------------------------------------------------

TEE_Result ClearCache(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
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
    CmdNode *n = params[0].memref.buffer;
    // 验证帐号密码
    if (!verifyTApasswd(n->taId, n->account, n->password)) {
        params[1].value.b = 0;
        return TEE_ERROR_ACCESS_DENIED;
    }

    // cache仅1个元素且命中
    if (CheckUUID(cache.ta[cache.head].id, n->taId) && cache.head == cache.tail) {
        cache.head = END_NULL;
        cache.tail = END_NULL;
        tloge("clear ta cache succeeded.\n");
        params[1].value.b = 1;
        return TEE_SUCCESS;
    }

    // cache仅1个元素且未命中
    if (!CheckUUID(cache.ta[cache.head].id, n->taId) && cache.head == cache.tail) {
        tloge("ta cache not fount.\n");
        params[1].value.b = 0;
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    // cache有2个或以上元素
    int32_t cur = cache.head;
    if (CheckUUID(cache.ta[cur].id, n->taId)) {
        cache.head = cache.ta[cur].next;
        tloge("clear ta cache succeeded.\n");
        params[1].value.b = 1;
        return TEE_SUCCESS;
    }
    int32_t nxt = cache.ta[cur].next;
    while (nxt != END_NULL) {
        TEE_UUID tmp = cache.ta[nxt].id;
        if (CheckUUID(tmp, n->taId)) {
            cache.ta[cur].next = cache.ta[nxt].next;
            if (nxt == cache.tail) {
                cache.tail = cur;
            }
            tloge("clear ta cache succeeded.\n");
            params[1].value.b = 1;
            return TEE_SUCCESS;
        }
        cur = nxt;
        nxt = cache.ta[nxt].next;
    }
    tloge("ta cache not found.\n");
    params[1].value.b = 0;
    return TEE_ERROR_ITEM_NOT_FOUND;
}