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

#define MAX_TA_NUM          16
#define MAX_KEY_NUM         16
#define MAX_STR_LEN         64
#define KEY_SIZE            128
#define MAX_CMD_SIZE        16
#define NODE_LEN            8


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
    int32_t cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;  // -1: empty; 0~MAX_TA_NUM: next cmd for search operation.
} CmdNode;

typedef struct _tagCmdQueue{
    CmdNode queue[MAX_CMD_SIZE];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first cmd for dequeue operation.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last cmd for enqueue operation.
} CmdQueue;

//internal function

//for initializition
void saveLocalKey(void *keyname, void *keyvalue, uint32_t keytype);

void restoreLocalKey(void *keyname, void *keyvalue, uint32_t keytype);

void initTACache(Cache cache);

void initCmdCache(CmdQueue *cmdqueue);

//for key management

void saveKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue, Cache *cache);

//for ta-auth
void addTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache) ;

void deleteTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache);

void searchTAState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache);

void attestTA();

#endif /* __KTA_H__ */