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

2、描述：KTA请求函数
```C
cmd CMD_SEND_REQUEST
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放请求
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
        );
```
3、描述：KA请求返回
```C
cmd CMD_RESPOND_REQUEST
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放请求结果
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放KTA处理结果
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
        );
```
### 与TA交互接口

4、描述：TA请求生成密钥
```C
cmd CMD_TA_GENERATE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放是否需要向kcm生成请求：固定为1（需要）
                                      //b为0表示生成请求结果失败，1表示生成请求结果成功（详见数据结构TEE_Param）
        TEE_PARAM_TYPE_NONE
        );
```

5、描述：TA请求查询密钥

```C
cmd CMD_KEY_SEARCH
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //存放返回密钥明文
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放是否需要向kcm生成请求：a为0表示不需要向kcm生成请求，1表示需要向kcm生成请求
                                      //b为0表示生成请求结果失败，1表示生成请求结果成功（详见数据结构TEE_Param）
        TEE_PARAM_TYPE_NONE
        );
```
6、描述：TA请求删除密钥缓存
```C
cmd CMD_KEY_DELETE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, //存放cmd结构体
        TEE_PARAM_TYPE_VALUE_OUTPUT, //返回删除结果
        TEE_PARAM_TYPE_VALUE_OUTPUT, //存放是否需要向kcm生成请求：固定为0（不需要）
        TEE_PARAM_TYPE_NONE
        );
```
7、描述：TA请求删除KCM中缓存密钥
```C
cmd CMD_KEY_DESTORY
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放kta本地删除结果：0表示失败，1表示成功
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //存放是否需要向kcm生成请求：固定为1（需要向kcm生成请求）
                                      //b为0表示生成请求结果失败，1表示生成请求结果成功（详见数据结构TEE_Param）
        TEE_PARAM_TYPE_NONE, 
        );
```
8、描述：KTA向TA返回结果
```C
cmd CMD_KCM_REPLY
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_MEMREF_OUTPUT, //返回请求结果
        TEE_PARAM_TYPE_NONE，
        TEE_PARAM_TYPE_NONE
        );
```
9、描述：TA删除所有kta内部保存的信息
```C
cmd CMD_CLEAR_CACHE
parm_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,  //存放cmd结构体
        TEE_PARAM_TYPE_VALUE_OUTPUT,  //返回请求结果：0表示失败，1表示成功
        TEE_PARAM_TYPE_NONE，
        TEE_PARAM_TYPE_NONE
        );
```

## KTA内部实现
### KTA数据结构说明

使用多重数组实现密钥/TA信息本地缓存

```C
/* command queue to store the commands */

typedef struct _tagParseCmdData{
    int32_t cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    uint8_t masterkey[KEY_SIZE];
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
} ParseCmdData;

typedef struct _tagCmdNode{
    int32_t cmd;
    uint8_t data[MAX_DATA_LEN];
    int32_t next;  // -1: empty; 0~MAX_TA_NUM: next cmd for search operation.
} CmdNode;

typedef struct _tagCmdQueue{
    CmdNode queue[MAX_CMD_SIZE];
    int32_t head;   // -1: empty; 0~MAX_TA_NUM: first cmd for dequeue operation.
    int32_t tail;   // -1: empty; 0~MAX_TA_NUM: last cmd for enqueue operation.
} CmdQueue;

```