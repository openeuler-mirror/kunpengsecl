#include <stdint.h>

#define MAX_TA_NUM 16 // test
#define MAX_KEY_NUM 16 // test
#define MAX_PASSWD_SIZE 16 // test
#define KEY_ID_SIZE 64 // test
#define KEY_SIZE 128 // test
#define MAX_CMD_SIZE 16 // test
#define NODE_LEN 8

typedef struct tee_uuid
{
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[NODE_LEN];
} TEE_UUID;


typedef struct DataCache{
    TaCache TaCache[MAX_TA_NUM];
    uint_32 firstTa;                  //Entry address for each search
    uint_32 lastTa;                   //for LRU
    uint_32 emptyBlock[MAX_TA_NUM];   //empty block

typedef struct TaCache{
    TEE_UUID TA_uuid;
    char passWd[MAX_PASSWD_SIZE];
    uint_32 nextTa;                   //If the value is -1, it means the last element
    keyNode keyNode[MAX_KEY_NUM];
    uint_32 firstKey;                 //Entry address for each search
    uint_32 lastKey;                  //for LRU
    uint_32 emptyBlock[MAX_KEY_NUM];  //empty block
}TaCache;

typedef struct keyNode{
    char keyId[KEY_ID_SIZE];
    char keyValue[KEY_SIZE];
    uint_32 nextKey; //If the value is -1, it means the last element
}keyNode;

/*以队列结构存储命令（链表实现）*/
typedef struct cmdNode{
    TEE_UUID TA_uuid;
    uint_32 cmdType;
    char keyId[KEY_ID_SIZE];
    cmdNode* next; 
}cmdNode;

typedef struct{
    uint_32 cmdNum;
    cmdNode* firstCmd;
    cmdNode* lastCmd;
}cmdCache;