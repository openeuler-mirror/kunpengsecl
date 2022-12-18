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
#include <cJSON.h>

#define PARAM_COUNT 4
#define AES_KEY_SIZE 32
#define RSA_PUB_SIZE 256
#define NONCE_SIZE 12
#define TAG_SIZE 16

const TEE_UUID ktaUuid = {
    0x435dcafa, 0x0029, 0x4d53, { 0x97, 0xe8, 0xa7, 0xa1, 0x3a, 0x80, 0xc8, 0x2e }
};

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
TEE_Result generateCmdDataKey(TEE_ObjectHandle key_obj){
    TEE_Result ret;
    TEE_Attribute attr = {0};
    uint8_t key_buffer[AES_KEY_SIZE] = {0};

    ret = TEE_AllocateTransientObject(TEE_TYPE_AES, AES_KEY_SIZE, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("fail to allocate aes transient object, ret 0x%x\n", ret);
        return ret;
    }
    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key_buffer, AES_KEY_SIZE);
    ret = TEE_PopulateTransientObject(key_obj, &attr, 1);
    if (ret != TEE_SUCCESS) {
        tloge("fail to populate aes transient object, ret 0x%x\n", ret);
        return ret;
    }

    ret = TEE_GenerateKey(key_obj, AES_KEY_SIZE, &attr, 1);
    if (ret != TEE_SUCCESS) {
        tloge("fail to generate aes key, ret 0x%x\n", ret);
        return ret;
    }
}

void encryptCmd(uint8_t *jsoncmd, uint32_t jsoncmd_size, TEE_ObjectHandle *key_obj, uint8_t *nonce_buff, uint8_t *tag_buff) {
    TEE_Result ret;
    TEE_OperationHandle oper_enc = NULL;
    uint8_t encrypted_buffer[jsoncmd_size];
    size_t encrypted_size = jsoncmd_size;
    size_t nonce_size = NONCE_SIZE;
    size_t tag_size = TAG_SIZE;

    ret = TEE_AllocateOperation(&oper_enc, TEE_ALG_AES_GCM, TEE_MODE_ENCRYPT, AES_KEY_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("fail to allocate aes encrypt operation, ret 0x%x\n", ret);
        return ret;
    }

    ret = TEE_SetOperationKey(oper_enc, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("fail to set rsa encrypt key, ret 0x%x\n", ret);
        TEE_FreeOperation(oper_enc);
        return ret;
    }
    TEE_GenerateRandom(nonce_buff, nonce_size);
    TEE_AEInit(oper_enc, nonce_buff, nonce_size, tag_size, 0, 0);

    ret = TEE_AEEncryptFinal(oper_enc, jsoncmd, jsoncmd_size, encrypted_buffer, encrypted_size, tag_buff, &tag_size);
    if (ret != TEE_SUCCESS) {
        tloge("fail to final aes encrypt, ret 0x%x\n", ret);
        TEE_FreeOperation(oper_enc);
        return ret;
    }
    memcpy_s(jsoncmd, jsoncmd_size, encrypted_buffer, encrypted_size);
}

void encryptKey(TEE_ObjectHandle *key_obj, uint8_t *encrypted_key){
    TEE_Result ret;
    TEE_ObjectHandle rsa_key_obj = NULL;

    ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, RSA_PUB_SIZE, &rsa_key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("fail to allocate rsa transient object, ret 0x%x\n", ret);
        return ret;
    }


   
};

void hex2char(uint32_t hex, uint8_t *hexchar, int32_t i) {
    for(i--; i >= 0; i--, hex >>= 4) {
        if ((hex & 0xf) <= 9)
            *(hexchar + i) = (hex & 0xf) + '0';
        else
            *(hexchar + i) = (hex & 0xf) + 'A' - 0x0a;
    }
}

void uuid2char(TEE_UUID uuid, uint8_t charuuid[33]) {
    int32_t i = 0;

    hex2char(uuid.timeLow, charuuid, 8);
    hex2char(uuid.timeMid, charuuid + 8, 4);
    hex2char(uuid.timeHiAndVersion, charuuid + 12, 4);
    for(i = 0; i < 2; i++){
        hex2char(uuid.clockSeqAndNode[i], charuuid + 16 + i * 2, 2);
    }
    for(i = 0; i < 6; i++){
        hex2char(uuid.clockSeqAndNode[i+2], charuuid + 20 + i * 2, 2);
    }
}

// transfer struct CmdNode to cJSON format
void cmdNode2cjson(CmdNode cmdnode, cJSON *cj) {
    uint8_t taid[33] = {0};
    uint8_t keyid[33] = {0};
    uint8_t masterkey[33] = {0};
    uint8_t ktauuid[33] = {0};
    // translate cmd
    cJSON_AddNumberToObject(cj, "cmd", cmdnode.cmd);
    // translate taid
    uuid2char(cmdnode.taId, taid[33]);
    cJSON_AddStringToObject(cj, "taid", taid[33]);
    // translate keyid
    uuid2char(cmdnode.keyId, keyid[33]);
    cJSON_AddStringToObject(cj, "keyid", keyid[33]);
    // translate masterkey
    uuid2char(cmdnode.masterkey, masterkey[33]);
    cJSON_AddStringToObject(cj, "masterkey", masterkey[33]);
    // translate account
    cJSON_AddStringToObject(cj, "account", cmdnode.account);
    // translate password
    cJSON_AddStringToObject(cj, "password", cmdnode.password);
    // translate kta uuid
    uuid2char(ktaUuid, ktauuid[33]);
    cJSON_AddStringToObject(cj, "ktauuid", ktauuid[33]);
}

void generateFinalRequest(CmdNode cmdnode, uint8_t *finalrequest){
    TEE_Result ret;
    TEE_ObjectHandle data_key = NULL;
    cJSON cmdjsonnode = {0};
    cJSON finalcmdjsonnode = {0};
    uint8_t nonce_buff[NONCE_SIZE] = {0};
    uint8_t tag_buff[TAG_SIZE] = {0};
    uint8_t encrypted_key[RSA_PUB_SIZE+1] = {0};
    /* get request data from cmdqueue,and generate final request*/
    ret = generateCmdDataKey(data_key);
    if (ret != TEE_SUCCESS) {
        tloge("fail to generate key, ret 0x%x\n", ret);
        return ret;
    }
    cmdNode2cjson(cmdnode, &cmdjsonnode);//cmdqueue.queue[cmdqueue.head]
    uint8_t *charRequest = cJSON_PrintUnformatted(&cmdjsonnode);
    encryptCmd(charRequest, strlen(charRequest), data_key, nonce_buff, tag_buff);
    encryptKey(data_key, encrypted_key);
    // translate key
    cJSON_AddStringToObject(&finalcmdjsonnode, "key", encrypted_key);
    // translate key_size
    cJSON_AddNumberToObject(&finalcmdjsonnode, "key_size", strlen(encrypted_key));
    // translate cmddata
    cJSON_AddStringToObject(&finalcmdjsonnode, "cmddata", charRequest);
    // translate data_size
    cJSON_AddNumberToObject(&finalcmdjsonnode, "data_size", strlen(charRequest));
    finalrequest = cJSON_PrintUnformatted(&finalcmdjsonnode);
}

TEE_Result SendRequest(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    CmdNode curNode;
    uint8_t *finalrequest = NULL;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL ||
        params[0].memref.size == 0) {
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

    //generate Request Return value for ka
    generateFinalRequest(curNode, finalrequest);
    errno_t err = memcpy_s(params[0].memref.buffer, sizeof(finalrequest), &finalrequest, sizeof(finalrequest));
    if(err != 0) {
        tloge("buffer is too short");
        return TEE_ERROR_SHORT_BUFFER;
    }
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

void char2uuid(uint8_t charuuid[33], TEE_UUID *uuid) {
    int32_t i = 0;
    uint8_t *stop = NULL;
    uint8_t buffer[3] = {0};
    uuid->timeLow = strtoul(charuuid, &stop, 16);
    uuid->timeMid = strtoul(stop, &stop, 16);
    uuid->timeHiAndVersion = strtoul(stop, &stop, 16);
    for(i = 0; i < 2; i++) {
        uuid->clockSeqAndNode[i] = strtoul(charuuid + 16 + i * 2, &stop, 16) >> (8 - i * 8);
    }
    for(i = 0; i < 6; i++) {
        buffer[0] = *(charuuid + 20 + i * 2);
        buffer[1] = *(charuuid + 21 + i * 2);
        uuid->clockSeqAndNode[i + 2] = strtoul(buffer, &stop, 16);
    }
}

// transfer cJSON format to struct CmdNode
void cjson2cmdNode(cJSON *cj, CmdNode *cmdnode) {
    cJSON *cjson_cmd = NULL;
    cJSON *cjson_taid = NULL;
    cJSON *cjson_keyid = NULL;
    cJSON *cjson_masterkey = NULL;
    cJSON *cjson_account = NULL;
    cJSON *cjson_password = NULL;
    // translate cmd
    cjson_cmd = cJSON_GetObjectItem(cj, "cmd");
    cmdnode->cmd = cJSON_GetNumberValue(cjson_cmd);
    // translate taid
    cjson_taid = cJSON_GetObjectItem(cj, "taid");
    char *taid = cJSON_GetStringValue(cjson_taid);
    char2uuid(taid, &cmdnode->taId);
    // translate keyid
    cjson_keyid = cJSON_GetObjectItem(cj, "keyid");
    char *keyid = cJSON_GetStringValue(cjson_keyid);
    char2uuid(keyid, &cmdnode->keyId);
    // translate masterkey
    cjson_masterkey = cJSON_GetObjectItem(cj, "masterkey");
    char *masterkey = cJSON_GetStringValue(cjson_masterkey);
    char2uuid(masterkey, &cmdnode->masterkey);
    // translate account
    cjson_account = cJSON_GetObjectItem(cj, "account");
    char *ac = cJSON_GetStringValue(cjson_account);
    for (int i=0; i<MAX_STR_LEN; i++) {
        cmdnode->account[i] = ac[i];
    }
    // translate password
    cjson_password = cJSON_GetObjectItem(cj, "password");
    char *pw = cJSON_GetStringValue(cjson_password);
    for (int i=0; i<MAX_STR_LEN; i++) {
        cmdnode->password[i] = pw[i];
    }
}

// transfer cJSON format to struct CmdRequest
void cjson2cmdRequest(cJSON *cj, CmdRequest *req) {
    cJSON *cjson_key = NULL;
    cJSON *cjson_keysize = NULL;
    cJSON *cjson_data = NULL;
    cJSON *cjson_datasize = NULL;
    // translate key
    cjson_key = cJSON_GetObjectItem(cj, "key");
    char *key = cJSON_GetStringValue(cjson_key);
    for (int i=0; i<KEY_SIZE; i++) {
        req->key[i] = key[i];
    }
    // translate key_size
    cjson_keysize = cJSON_GetObjectItem(cj, "keysize");
    req->key_size = cJSON_GetNumberValue(cjson_keysize);
    // translate cmddata
    cjson_data = cJSON_GetObjectItem(cj, "cmddata");
    char *data = cJSON_GetStringValue(cjson_data);
    for (int i=0; i<MAX_DATA_LEN; i++) {
        req->cmddata[i] = data[i];
    }
    // translate data_size
    cjson_datasize = cJSON_GetObjectItem(cj, "datasize");
    req->data_size = cJSON_GetNumberValue(cjson_datasize);
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
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.buffer == NULL || params[0].memref.size == 0) {
        tloge("Bad expected parameter value");
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