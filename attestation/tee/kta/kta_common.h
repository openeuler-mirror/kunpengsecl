/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: waterh2o/wucaijun
Create: 2022-11-02
Description: initialize module in kta.
	1. 2022-11-02	waterh2o/wucaijun
		define the structures.
*/

#ifndef __KTA_H__
#define __KTA_H__

#include <tee_defines.h>
#include <tee_log.h>

#define MAX_TA_NUM          16
#define MAX_KEY_NUM         16
#define MAX_STR_LEN         64
#define KEY_SIZE            128
#define MAX_QUEUE_SIZE      16
#define NODE_LEN            8
#define MAX_DATA_LEN        1024
#define END_NULL            -1

static const char *signed_pubkey_path = ""; //to be set
static const char *kcm_encodekey_path = ""; //to be set
static const char *kms_pubkey_path = ""; //to be set

typedef struct _tagKeyInfo{
    TEE_UUID    id;
    uint8_t value[KEY_SIZE];
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next key for search operation.
} KeyInfo;

typedef struct _tagTaInfo{
    TEE_UUID    id;
    TEE_UUID    masterkey;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next ta for search operation.
    KeyInfo key[MAX_KEY_NUM];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first key for dequeue operation.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last key for enqueue operation.
} TaInfo;


typedef struct _tagCache{
    TaInfo  ta[MAX_TA_NUM];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first ta for dequeue operation.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last ta for enqueue operation.
    
} Cache;

/* command queue to store the commands */

typedef struct _tagCmdNode{
    int32_t     cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    TEE_UUID    masterkey;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
} CmdNode;

typedef struct _tagCmdQueue{
    CmdNode queue[MAX_QUEUE_SIZE];
    int32_t head;   // 0~MAX_TA_NUM: first cmd for dequeue operation.
    int32_t tail;   // 0~MAX_TA_NUM: last cmd for enqueue operation.
} CmdQueue;

typedef struct _tagReplyData{
    TEE_UUID    taId;
    TEE_UUID    keyId;
    uint8_t keyvalue[KEY_SIZE];
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next reply for search operation.
} ReplyNode;

typedef struct _tagReplyQueue{
    ReplyNode list[MAX_QUEUE_SIZE];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first reply for key generate.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last reply for key generate.
} ReplyCache;

typedef struct _tagRequest{
    /*
    when using as Intermediate Request:
    Symmetric key plaintext and CmdData (json) plaintext
    ====================================================
    when using as final request:
    json:  key:*****;cmdData:*****； 
    key has been encrypted by the kcm-pub
    cmddata has been encrypted by the key
    */
    uint8_t key[KEY_SIZE]; 
    uint32_t key_size;
    uint8_t cmddata[MAX_DATA_LEN];
    uint32_t data_size;
} CmdRequest;


//internal function

//for initializition

TEE_Result saveKeyandCert(char *certname, uint8_t *certvalue, size_t certsize);

TEE_Result restoreKeyandCert(char *certname, uint8_t *buffer, size_t *buf_len);

TEE_Result initStructure();

//for reset key and cert

TEE_Result reset_all();

TEE_Result reset(char *name);

//for key management



//for ta-auth
bool verifyTApasswd(TEE_UUID TA_uuid, char *account, char *password);

bool CheckUUID(TEE_UUID id1,TEE_UUID id2);

void attestTA(TEE_UUID TA_uuid);

#endif /* __KTA_H__ */