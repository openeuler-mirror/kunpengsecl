#### KA介绍

KA在本方案中担任了中间件的角色，KA负责帮助KTA进行初始化，并对KTA中请求队列进行定期轮训，判断KTA中是否有密钥相关请求。KA通过借助CGO向KTALIB中的功能进行调用，以满足KCMS侧与KTA之间的信息交互。KA主要🈶️katools模块进行实现，主要用Go语言进行开发，由于KA涉及与KTA与KCMS两个实体之间的信息交互，因而无法作为一个独立的实体进行单元测试，故而目前未设置测试用例，而将测试用例放到与KTA与KCMS侧进行实现。
#### KTALIB介绍

KTALIB在本方案中担任库的角色，主要用于满足KA对KTA的调用，在TEE视角中KA属于一个CA，而KTALIB则属于类似于TEE内部的QCALIB，符合TEE的开发和要求，在使用TEE内部提供的唯一接口TEEC_InvokeCommand基础之上，在该lib库中实现对指定TA的调用过程，并实现了对TEE内部的函数调用。该lib库使用C语言进行开发，具备KTA初始化过程、KTA命令获取等过程。

#### KA接口
KA作为一个TEE内部TA的CA，表示KTA的使能端，使用Go语言编写，接口函数主要有：
```golang
func KaMain(addr string, id int64)
```
接口描述：使能KTA并对KTA请求进行轮训操作 
参数1【传入】：服务端地址。  
参数2【传入】：ka所属的ClientID。

#### KTALIB接口
KTALIB中包含了对KTA的相关操作，包括与KTA建立会话、KTA初始化操作、KTA命令获取操作、KTA命令请求操作、与KTA断开连接操作

```c
TEEC_Result InitContextSession(uint8_t* ktapath) 
```
接口描述：初始化上下文和会话
参数1【传入】：kta路径。

```c
TEEC_Result KTAinitialize(
    struct buffer_data* kcmPubKey, 
    struct buffer_data* ktaPubCert, 
    struct buffer_data* ktaPrivKey, 
    struct buffer_data *out_data)
```
接口描述：初始化KTA过程
参数1【传入】：KCM的公钥。  
参数2【传入】：KTA公钥证书。
参数3【传入】：KTA私钥。  
参数4【传出】：KTA侧传出的使用JSON格式加密的数据。

```c
TEEC_Result KTAgetCommand(struct buffer_data* out_data, uint32_t* retnum)
```
接口描述：从KTA侧获取命令请求
参数1【传出】：获取KTA侧的命令请求。  
参数2【传出】：存放剩余请求数量。

```c
TEEC_Result KTAsendCommandreply(struct buffer_data* in_data)
```
接口描述：向KTA返回密钥请求结果
参数1【传入】：密钥请求参数。

```c
void KTAshutdown() 
```
接口描述：关闭KTA的连接
