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
Description: kta manages the TA's key cache in the TEE.
	1. 2022-11-02	waterh2o/wucaijun
		define the core structures for key caching.
*/

#ifndef __KTA_H__
#define __KTA_H__

#include <stdint.h>


#define MAX_TA_NUM          16
#define MAX_KEY_NUM         16
#define MAX_STR_LEN         64
#define KEY_SIZE            128
#define MAX_CMD_SIZE        16
#define NODE_LEN            8

typedef struct _tagUuid
{
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t  clockSeqAndNode[NODE_LEN];
} UUID;

typedef struct _tagKeyInfo{
    UUID    id;
    uint8_t value[KEY_SIZE];
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next key for search operation.
} KeyInfo;

typedef struct _tagTaInfo{
    UUID    id;
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
    UUID    taId;
    UUID    keyId;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;  // -1: empty; 0~MAX_TA_NUM: next cmd for search operation.
} CmdNode;

typedef struct _tagCmdQueue{
    CmdNode queue[MAX_CMD_SIZE];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first cmd for dequeue operation.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last cmd for enqueue operation.
} CmdQueue;

#endif /* __KTA_H__ */