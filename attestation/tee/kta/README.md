# KTA

使用C语言实现

## 环境准备

在开始编译kta之前，先执行本目录下的**prepare-tee-sdk.sh**脚本文件准备必要的编译环境

## 对外接口（通过TA的固定调用接口实现）
### 与KA交互接口
1、描述：KTA初始化
```C
cmd CMD_KTA_INITIALIZE
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放初始化结果
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放KTA公钥证书
        TEE_PARAM_TYPE_MEMREF_OUTPUT,  
        TEE_PARAM_TYPE_NONE
        );
```

2、描述：KTA初始化结果返回

```c
cmd CMD_KTA_INITREPLY
parm_type = TEEC_PARAM_TYPES(
    TEE_PARAM_TYPE_MEMREF_INPUT, //存放KCM生成的加密密钥
    TEE_PARAM_TYPE_MEMREF_INPUT, //存放KMS公钥
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE,
    );
```
3、描述：KA轮询
```C
cmd CMD_SEND_REQUEST
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放请求列表
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放请求数量
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放需要更新可信状态的TAuuid列表
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放需要更新可信状态的TA可信状态查询结果
        );
```
4、描述：KA请求返回
```C
cmd CMD_RESPOND_REQUEST
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放请求结果
        TEE_PARAM_TYPE_VALUE_INPUT, //存放请求数量
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        );
```
### 与TA交互接口

5、描述：TA请求生成/查询密钥

```C
cmd CMD_KEY_SEARCH
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放账号密码，uuid
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放密钥id
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_OUTPUT //返回密钥明文
        );
```
6、描述：TA请求删除密钥缓存
```C
cmd CMD_KEY_DELETE
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放账号密码，uuid
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放密钥id
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT //返回删除结果
        );
```
7、描述：TA请求删除密钥
```C
cmd CMD_KEY_DESTORY
parm_type = TEEC_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放账号密码，uuid
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放密钥id
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_OUTPUT //返回删除结果
        );
```
8、描述：KTA向TA返回结果（用于异步实现）
```C
cmd CMD_KEY_REPLY
```

## KTA内部实现
### KTA数据结构说明

使用多重数组实现密钥/TA信息本地缓存

```C
typedef struct _tagKeyInfo{
    TEE_UUID    id;
    uint8_t value[KEY_SIZE];
    int32_t next;
} KeyInfo;

typedef struct _tagTaInfo{
    TEE_UUID    id;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;
    KeyInfo key[MAX_KEY_NUM];
    int32_t head;
    int32_t tail;
} TaInfo;


typedef struct _tagCache{
    TaInfo  ta[MAX_TA_NUM];
    int32_t head;
    int32_t tail;
} Cache;

typedef struct _tagCmdNode{
    int32_t cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
    int32_t next;

typedef struct _tagCmdQueue{
    CmdNode queue[MAX_CMD_SIZE];
    int32_t head;
    int32_t tail;
} CmdQueue;
```

### 初始化
#### 函数声明

描述：初始化KTA内部数据存储结构
参数：teepubkey[IN]TEE设备公钥，signedpubkey[OUT]签名后kta公钥，cache[OUT]数据存储结构，cmdqueue[OUT]请求存储结构

```C
TEE_Result KTAInitialize(void *teepubkey, void *signedpubkey, Cache *cache, CmdQueue *cmdqueue);
```

描述：保存密钥
参数：privkeyname[IN]存储的密钥名称，key[IN]需要存储的密钥

```C
TEE_Result SaveLocalKey(void *keyname, void *keyvalue)
```

描述：读取保存的密钥
参数：privkeyname[IN]读取的密钥名称，key[OUT]读取的密钥

```C
TEE_Result RestoreLocalKey(void *keyname, void *keyvalue)
```

描述：初始化本地缓存
参数：datacache[OUT]KTA内部缓存数据结构

```C
TEE_Result InitCache(Cache *cache)
```

### 密钥管理：实现密钥存取、维护密钥表
#### 函数声明

描述：KTA本地查询密钥，并更新密钥表
参数：TA_uuid[IN]TA的uuid值，keyid[IN]TA需要查询的密钥id值，keycache[IN/OUT]密钥缓存数据结构，keyvalue[OUT]返回的密钥

```C
TEE_Result SearchKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache, char *keyvalue)
```
描述：KTA存储KA返回的密钥，更新密钥表
参数：TA_uuid[IN]TA的uuid值，keyid[IN]KA返回的密钥id，keyvalue[IN]返回的密钥明文，keycache[IN/OUT]密钥缓存数据结构

```C
TEE_Result SaveKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue, Cache *cache)
```
描述：KTA删除本地密钥
参数：TA_uuid[IN]TA的uuid值，keyid[IN]TA需要删除的密钥id值，keycache[IN/OUT]密钥缓存数据结构

```C
TEE_Result DeleteKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache)
```
描述：删除密钥表
参数：keycache[IN]密钥缓存数据结构

```C
TEE_Result DestoryCache(Cache *cache)
```

### KTA数据交互

#### 函数声明

描述：向KA传递请求

```C
TEE_Result SendRequest()
```

描述：接收KA请求处理结果

```C
TEE_Result HandleReply()
```

描述：对请求信息进行加密

```c
TEE_Result EncodeRequest(void *kmskey, cmdCache cmdcache)
```

描述：对请求信息进行解密

```C
TEE_Result DncodeRequest(void *kmskey, cmdCache cmdcache)
```
描述：KTA向TA返回结果（用于异步实现）
```C
cmd CMD_KEY_REPLY
```

### 权限管理：用于管理本地TA信息，进行TA鉴权（包括TA权限和可信状态两部分） //可能需要KA传入TA的基准值

实现KA轮询KTA查询TA可信状态

#### 函数声明

描述：将一个TA账号密码添加至数据表（问题：初始账号密码是谁传过来的？）
```C
TEE_Result addTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache)
```
描述：将一个TA状态从TA表删除
```C
TEE_Result deleteTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache)
```
描述：更新一个TA状态
```C
TEE_Result updateTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache)
```
描述：本地调用QTA验证TA的可信状态
```C
bool attestTA()
```
