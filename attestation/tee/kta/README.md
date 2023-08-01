# KTA

使用C语言实现

## 环境准备

在开始编译kta之前，先执行本目录下的**prepare-tee-sdk.sh**脚本文件准备必要的编译环境

## 对外接口（通过TA的固定调用接口实现）
### 与KA交互接口
1、描述：KTA初始化
```C
cmd CMD_KTA_INITIALIZE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,   //存放KCM公钥
        TEE_PARAM_TYPE_MEMREF_INPUT,   //存放KTA公钥证书
        TEE_PARAM_TYPE_MEMREF_INPUT,   //存放KTA私钥
        TEE_PARAM_TYPE_VALUE_OUTPUT    //存放KTA公钥证书（返回）
        );
```

2、描述：KTA获取TA哈希
```C
cmd CMD_GET_TAHASH
param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放TA的哈希
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_INPUT //存放KA发送的哈希数量：0<a<=32
        );
```

3、描述：KTA请求发送
```C
cmd CMD_SEND_REQUEST
param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放一个请求
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放当前请求队列中的请求数量
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
        );
```

4、描述：KA请求返回
```C
cmd CMD_RESPOND_REQUEST
param_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放请求结果
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放KTA处理结果, 0表示失败，1表示成功
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        );
```
### 与TA交互接口

5、描述：TA请求生成密钥
```C
cmd CMD_TA_GENERATE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放是否需要向kcm生成请求：a固定为1（需要）
                                      //b为0表示生成请求结果失败，1表示生成请求结果成功（详见数据结构TEE_Param）
        TEE_PARAM_TYPE_MEMREF_INPUT  //存放TA的两个哈希值
        );
```

6、描述：TA请求查询密钥
```C
cmd CMD_KEY_SEARCH
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放返回密钥明文
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放是否需要向kcm生成请求：a为0表示不需要向kcm生成请求，1表示需要向kcm生成请求
                                      //b为0表示生成请求结果失败，1表示生成请求结果成功（详见数据结构TEE_Param）
        TEE_PARAM_TYPE_MEMREF_INPUT  //存放TA的两个哈希值
        );
```

7、描述：TA请求删除密钥缓存
```C
cmd CMD_KEY_DELETE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放cmd结构体
        TEE_PARAM_TYPE_VALUE_OUTPUT, //返回删除结果
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放是否需要向kcm生成请求：a固定为0（不需要）
        TEE_PARAM_TYPE_MEMREF_INPUT  //存放TA的两个哈希值
        );
```

8、描述：KTA向TA返回结果
```C
cmd CMD_KCM_REPLY
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //返回请求结果
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_INPUT  //存放TA的两个哈希值
        );
```

9、描述：TA删除所有KTA内部保存的信息
```C
cmd CMD_CLEAR_CACHE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //返回请求结果：a为0表示失败，1表示成功
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_INPUT  //存放TA的两个哈希值
        );
```

## KTA内部实现
### KTA数据结构说明

使用多重数组实现密钥/TA信息本地缓存

```C
/* Cache to store the info of Ta and key */
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

/* CmdQueue to store the commands */
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

/* HashCache to store the hash values of ta */
typedef struct _tagHashValues{
    uint8_t taId[UUID_LEN];
    char mem_hash[HASH_SIZE];
    char img_hash[HASH_SIZE];
} HashValue;

typedef struct _tagHashCache{
    HashValue hashvalue[MAX_TAHASH_NUM + 1];
    int32_t head;   // 0~MAX_TAHASH_NUM: first ta hash.
    int32_t tail;   // 0~MAX_TAHASH_NUM: last ta hash.
} HashCache;

/* ReplyCache to store the reply of ta's request */
typedef struct _tagReplyNode{
    int32_t tag;    //a tag to identify reply: 1 for generate reply, 2 for delete reply
    TEE_UUID    taId;
    TEE_UUID    keyId;
    union {
        uint8_t keyvalue[KEY_SIZE];
        int32_t flag;   //a flag to identify if the key is deleted successfully: 1 for deleted, 0 for not
    };
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next reply for search operation.
} ReplyNode;

typedef struct _tagReplyQueue{
    ReplyNode list[MAX_QUEUE_SIZE];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first reply for key generate.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last reply for key generate.
} ReplyCache;
```