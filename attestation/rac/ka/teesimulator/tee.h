/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

//a simulation of tee

#ifndef __TEE_SIM__
#define __TEE_SIM__

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
//#include "tee_client_api.h"
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
#define TEEC_Error(fmt, args...) printf("%s: " fmt, __func__, ## args)
typedef enum TEEC_ReturnCode TEEC_Result;
enum TEEC_ReturnCode {
    TEEC_SUCCESS = 0x0,
    TEEC_ERROR_GENERIC = 0xFFFF0000,         /* generic error occurs */
    TEEC_ERROR_SECURITY = 0xFFFF000F,        /* security error occurs */
};
#define TEEC_PARAM_TYPES(param0Type, param1Type, param2Type, param3Type) \
    ((param3Type) << 12 | (param2Type) << 8 | (param1Type) << 4 | (param0Type))
enum TEEC_ParamType {
    TEEC_NONE = 0x0,  /* unused parameter */
    TEEC_VALUE_INPUT = 0x01,  /* input type of value, refer TEEC_Value */
    TEEC_VALUE_OUTPUT = 0x02, /* output type of value, refer TEEC_Value */
    TEEC_VALUE_INOUT = 0x03,  /* value is used as both input and output, refer TEEC_Value */
    TEEC_MEMREF_TEMP_INPUT = 0x05,  /* input type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_OUTPUT = 0x06, /* output type of temp memory reference, refer TEEC_TempMemoryReference */
    TEEC_MEMREF_TEMP_INOUT = 0x07,  /* temp memory reference used as both input and output,
                                       refer TEEC_TempMemoryReference */
    TEEC_ION_INPUT = 0x08,  /* input type of icon memory reference, refer TEEC_IonReference */
    TEEC_ION_SGLIST_INPUT = 0x09, /* input type of ion memory block reference, refer TEEC_IonSglistReference */
    TEEC_MEMREF_SHARED_INOUT = 0x0a, /* no copy mem */
    TEEC_MEMREF_WHOLE = 0xc, /* use whole memory block, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INPUT = 0xd, /* input type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_OUTPUT = 0xe, /* output type of memory reference, refer TEEC_RegisteredMemoryReference */
    TEEC_MEMREF_PARTIAL_INOUT = 0xf /* memory reference used as both input and output,
                                        refer TEEC_RegisteredMemoryReference */
};
enum TEEC_LoginMethod {
    TEEC_LOGIN_PUBLIC = 0x0,            /* no Login data is provided */
    TEEC_LOGIN_USER,                    /* Login data about the user running the
                                           Client Application process is provided */
    TEEC_LOGIN_GROUP,                   /* Login data about the group running
                                           the Client Application process is provided */
    TEEC_LOGIN_APPLICATION = 0x4,       /* Login data about the running Client
                                           Application itself is provided */
    TEEC_LOGIN_USER_APPLICATION = 0x5,  /* Login data about the user running the
                                           Client Application and about the
                                           Client Application itself is provided */
    TEEC_LOGIN_GROUP_APPLICATION = 0x6, /* Login data about the group running
                                           the Client Application and about the
                                           Client Application itself is provided */
    TEEC_LOGIN_IDENTIFY = 0x7,          /* Login data is provided by REE system */
};
typedef struct {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEEC_UUID;
struct ListNode {
    struct ListNode *next;  /* point to next node  */
    struct ListNode *prev;  /* point to prev node */
};
# define __SIZEOF_SEM_T	32
typedef union
{
  char __size[__SIZEOF_SEM_T];
  long int __align;
} sem_t;

typedef struct {
    int32_t fd;
    uint8_t *ta_path;
    struct ListNode session_list;
    struct ListNode shrd_mem_list;
    union {
        struct {
            void *buffer;
            sem_t buffer_barrier;
        } share_buffer;
        uint64_t imp;          /* for adapt */
    };
} TEEC_Context;
typedef struct {
    uint32_t session_id;
    TEEC_UUID service_id;
    uint32_t ops_cnt;
    union {
        struct ListNode head;
        uint64_t imp;          /* for adapt */
    };
    TEEC_Context *context;
} TEEC_Session;
typedef struct {
    void *buffer;
    uint32_t size;
} TEEC_TempMemoryReference;
typedef struct {
    void *buffer;
    uint32_t size;
    uint32_t flags;         /* reference to TEEC_SharedMemCtl */
    uint32_t ops_cnt;
    bool is_allocated;      /* identify whether the memory is registered or allocated */
    union {
        struct ListNode head;
        void* imp;          /* for adapt, imp is not used by system CA, only for vendor CA */
    };
    TEEC_Context *context;
} TEEC_SharedMemory;
/*
 * the corresponding param types are
 * TEEC_MEMREF_WHOLE/TEEC_MEMREF_PARTIAL_INPUT
 * TEEC_MEMREF_PARTIAL_OUTPUT/TEEC_MEMREF_PARTIAL_INOUT
 */
typedef struct {
    TEEC_SharedMemory *parent;
    uint32_t size;
    uint32_t offset;
} TEEC_RegisteredMemoryReference;

/*
 * the corresponding param types are
 * TEEC_VALUE_INPUT/TEEC_VALUE_OUTPUT/TEEC_VALUE_INOUT
 */
typedef struct {
    uint32_t a;
    uint32_t b;
} TEEC_Value;

typedef struct {
    int ion_share_fd;
    uint32_t ion_size;
} TEEC_IonReference;
typedef union {
    TEEC_TempMemoryReference tmpref;
    TEEC_RegisteredMemoryReference memref;
    TEEC_Value value;
    TEEC_IonReference ionref;
} TEEC_Parameter;
#define TEEC_PARAM_NUM 4 /* teec param max number */
typedef struct {
    uint32_t started;     /* 0 means cancel this operation, others mean to perform this operation */
    uint32_t paramTypes;  /* use TEEC_PARAM_TYPES to construct this value */
    TEEC_Parameter params[TEEC_PARAM_NUM];
    TEEC_Session *session;
    bool cancel_flag;
} TEEC_Operation;

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);

void TEEC_FinalizeContext(TEEC_Context *context);

TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
    const TEEC_UUID *destination, uint32_t connectionMethod,
    const void *connectionData, TEEC_Operation *operation,
    uint32_t *returnOrigin);

void TEEC_CloseSession(TEEC_Session *session);

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin);
    
#endif