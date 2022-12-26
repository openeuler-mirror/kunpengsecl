# TEE设计文档

<!-- TOC -->

  - [TEE特性实现](#tee特性实现)
      - [远程证明特性](#远程证明特性)
          - [实体介绍](#实体介绍)
              - [QCA_DEMO介绍](#qca_demo介绍)
              - [ATTESTER_DEMO介绍](#attester_demo介绍)
              - [VERIFIER_LIB介绍](#verifier_lib介绍)
              - [AK_Service介绍](#ak_service介绍)
          - [接口介绍](#接口介绍)
              - [QCA接口](#qca接口)
              - [ATTESTER接口](#attester接口)
              - [AK_Service接口](#ak_service接口)
          - [流程架构图](#流程架构图)
              - [最小实现](#最小实现)
              - [独立实现](#独立实现)
              - [整合实现](#整合实现)

<!-- TOC -->

## 远程证明特性

TEE远程证明是鲲鹏安全生态开源组件鲲鹏安全库的一个重要特性，支撑基于鲲鹏平台构建开源机密计算解决方案。

当数据中心管理工具/管理员、云服务基础设施编排工具、密钥管理中心/模型提供方希望获取目标服务器上TEE中TA的可信状态时，需要触发TEE远程证明特性的功能。

### 实体介绍

#### QCA_DEMO介绍

QCA_DEMO在本方案中担任了服务端的角色，主要功能是本地调用QCA_LIB获取TEE中TA的可信报告，然后通过提供一个接口QAPI与位于其他平台的客户端进行交互，传输可信报告。其下分有main.go、qapi.go、qcatools.go三个模块，各自实现不同的功能。另外，由于QCA_DEMO采用Go语言开发，而QCA_LIB采用C语言开发，所以QCA_DEMO同时还借助CGO机制，提供了将C语言编写的可信报告转换为Go语言编写的可信报告的功能。

#### ATTESTER_DEMO介绍

ATTESTER_DEMO在本方案中担任了客户端的角色，主要功能是将从远程获取的TEE中TA的可信报告，本地调用VERIFIER_LIB进行可信验证，包含身份验证和完整性验证，并向管理员返回验证结果。其下分有main.go、attestertools.go两个模块，各自实现不同的功能。另外，由于ATTESTER_DEMO采用Go语言开发，而VERIFIER_LIB采用C语言开发，所以ATTESTER_DEMO同时还借助CGO机制，提供了将Go语言编写的可信报告转换为C语言编写的可信报告的功能。

#### VERIFIER_LIB介绍

VERIFIER_LIB实现TA完整性策略引擎，帮助ATTESTER_DEMO完成TA完整性判定。其下主要分有teeverifier.c、teeverifier.h、common.h三个文件，其中teeverifier.h是teeverifier.c对应的头文件，定义了可向外部暴露的接口，common.h定义了库所用到的各个常量、数据结构、内部函数等，而teeverifier.c则是对外接口的具体功能实现。

#### AK_Service介绍

AK_Service作为证明密钥服务端，分场景实现对TA的AKey Cert进行数字签名的服务。其中，RestAPI向用户提供信息维护服务，ClientAPI接收目标平台AK生成请求， AK Issuer实现相应协议帮助生成AK，Crypto实现必要的密码算法。

### 接口介绍

#### QCA接口

##### qcatools方法描述

QCA Demo的工具包，用以支持QCA Demo初始化命令行参数、初始化配置、与QCA Lib进行交互等。  
qcatools的对外方法如下：
```go
func InitFlags()
```
方法描述：初始化QCA Demo启动时的命令行参数。  
可用命令行参数如下：
```
-C, --scenario int32   设置QCA Demo的使用场景
-S, --server string    指定QCA Demo可以被客户端连接的IP地址
```
目前支持的场景有：
```go
RA_SCENARIO_NO_AS = 0 // 无AKS场景，对应最小实现
RA_SCENARIO_AS_NO_DAA = 1 // 有AKS无DAA场景
RA_SCENARIO_AS_WITH_DAA = 2 // 有AKS有DAA场景
```
***
```go
func LoadConfigs()
```
方法描述：加载预定义的配置。  
目前的默认配置为：
```yaml
qcaconfig:
  server: 127.0.0.1:40007
  akserver: 127.0.0.1:40008
  scenario: 0
  nodaaacfile: ./nodaa-ac.crt
  daaacfile: ./daa-ac.crt
```
***
```go
func HandleFlags()
```
方法描述：处理命令行参数。
***
```go
func GetTAReport(ta_uuid []byte, usr_data []byte, with_tcb bool) []byte
```
方法描述：调用QCA Lib接口获取TA的完整性报告。  
参数1：指定TA的唯一标识符UUID。  
参数2：用户传入的挑战数据，如nonce值，用以防重放攻击。  
参数3：指明是否携带TCB度量值。  
返回值：TA的完整性报告。
***
```go
func GenerateAKCert() ([]byte, error)
```
方法描述：根据不同使用场景请求QCA Lib返回相应证书。  
返回值1：DER格式的AK证书，无AKS场景返回为空。  
返回值2：错误输出。
***
```go
func SaveAKCert(cert []byte) error
```
方法描述：将AKS签发的AK证书保存入TEE环境。  
参数：DER格式的AK证书。  
返回值：错误输出。
***

##### qapi方法描述

QCA Demo与外交互的接口，向外提供TA的完整性报告。  
qapi的对外方法如下：
```go
func StartServer()
```
方法描述：QCA Demo的启动入口。
>QCA Demo启动后，若使用场景为有AKS场景，则会先检查本地指定路径下是否存有AKS签发的AK证书。若有，那么跳过后续与QCA Lib及AKS的交互步骤，直接开始监听自己对外提供的服务端口；若没有，那么需要发起与QCA Lib和AKS的交互，并将最终AKS签发的AK证书存于本地指定路径。
***
```go
func DoGetTeeReport(addr string, in *GetReportRequest) (*GetReportReply, error)
```
方法描述：供外部平台调用的接口，用以获取指定TA的完整性报告。  
参数1：待连接服务端的IP:Port地址，这里的服务端即QCA Demo。  
参数2：gRPC请求参数，包含uuid、nonce、with_tcb三个字段。  
返回值1：gRPC响应参数，包含TA的完整性报告的字节数组。
返回值2：错误输出。
***
```go
func (s *service) GetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error)
```
方法描述：gRPC中对应获取指定TA完整性报告的服务。  
参数1：服务请求的上下文信息。  
参数2：gRPC请求参数，包含uuid、nonce、with_tcb三个字段。  
返回值1：gRPC响应参数，包含TA的完整性报告的字节数组。
返回值2：错误输出。
***

##### aslib方法描述

QCA Demo与AK Service交互的接口，用以请求AKS签发AK证书。  
aslib的对外方法如下：
```go
func GetAKCert(oldAKCert []byte, scenario int32) ([]byte, error)
```
方法描述：通过AKS提供的clientapi请求AKS签发指定场景的AK证书。  
参数1：TEE环境中自签名的AK证书。  
参数2：指定服务的使用场景，主要是NoDAA/DAA场景。  
返回值1：由AKS重新签发的AK证书。  
返回值2：错误输出。
***

#### Attester接口

##### attestertools方法描述

Attester的工具包，用以支持Attester Demo初始化命令行参数、初始化配置、与QCA Demo进行交互等。  
attestertools的对外方法如下：
```go
func InitFlags()
```
方法描述：初始化Attester Demo启动时的命令行参数。  
可用命令行参数如下：
```
-B, --basevalue string   设置基准值文件的读取路径
-M, --mspolicy int       设置待使用的度量策略
-S, --server string      指定待连接的服务器端口
-T, --test               开启测试模式，使用固定的nonce值
-U, --uuid string        指定待验证的TA
-V, --version            打印版本号并退出程序
```
***
```go
func LoadConfigs()
```
方法描述：加载预定义的配置。  
目前的默认配置为：
```yaml
attesterconfig:
  server: 127.0.0.1:40007
  basevalue: "./basevalue.txt"
  mspolicy: 2
  uuid: f68fd704-6eb1-4d14-b218-722850eb3ef0
```
***
```go
func HandleFlags()
```
方法描述：处理命令行参数。
***
```go
func StartAttester()
```
方法描述：Attester Demo的启动入口。
>用户可通过读取Attester Demo的运行日志判断指定TA的度量结果。
***

##### VERIFIER_LIB方法描述

VERIFIER_LIB为Attester demo提供可信验证支持，返回验证结果给用户，接口主要有：
```c
int tee_verify_report(buffer_data *data_buf,buffer_data *nonce,int type, char *filename);
```
接口描述：对可信报告进行身份验证和完整性验证  
参数1：可信报告缓冲区指针，即通过事先调用QCA_LIB中RemoteAttestReport函数所更新的report参数  
参数2：用户提供的一个随机数，需要与可信报告中指定位置的nonce值进行比对，用于防重放攻击  
参数3：验证类型，即度量策略，1为仅比对img-hash值，2为仅比对hash值，3为同时比对img-hash和hash两个值  
参数4：基准值文件路径，可从该文件中读取基准值与可信报告中的度量值进行比对  
返回值：验证结果（0或-1或-2或-3）  
相应的返回值定义如下：
```c
enum error_status_code {
    TVS_ALL_SUCCESSED = 0, // 可信验证通过
    TVS_VERIFIED_NONCE_FAILED = -1, // nonce值不一致
    TVS_VERIFIED_SIGNATURE_FAILED = -2, // 签名或证书验证失败
    TVS_VERIFIED_HASH_FAILED = -3, // 度量值验证失败
};
```
***
本接口内部由以下三个函数实现对应功能：
```c
bool tee_verify_nonce(buffer_data *buf_data,buffer_data *nonce);
```
接口描述：验证可信报告中的nonce值是否与用户生成的一致  
参数1：可信报告缓冲区指针，即通过事先调用QCA_LIB中RemoteAttestReport函数所更新的report参数  
参数2：用户提供的nonce值缓冲区指针  
返回值：验证结果（true or false）  
***
```c
bool tee_verify_signature(buffer_data *report);
```
接口描述：验证报告签名和证书有效性，例如使用DRK证书对签名数据进行验签(noas)  
参数1：可信报告缓冲区指针，即通过事先调用QCA_LIB中RemoteAttestReport函数所更新的report参数  
返回值：验证结果（true or false）  

**ak_cert对应的固定字段、属性字段和数据字段：**

注：如果为noas情况，需要将akcert转换成如下的数据类型，从中获取到对应的ak_pub、sign_drk以及cert_drk等数据
```c
#define KEY_PURPOSE_SIZE 32
struct ak_cert
{
    uint32_t version;
    uint64_t ts;
    char purpose[KEY_PURPOSE_SIZE];
    uint32_t param_count;
    struct ra_params params[0];
    /* following buffer data:
     * (1)qta_img_hash []
     * (2)qta_mem_hash []
     * (3)reserverd []
     * (4)ak_pub []
     * (5)sign_drk []
     * (6)cert_drk []
     */
} __attribute__((__packed__));
```

**验证过程：**
1. 通过传入的缓冲区类型的report解析出对应的结构体类型的报告
2. 使用DRK证书对sign_drk进行验签（noas情况）
3. 从akcert中获取akpub对sign_ak进行验签
4. 返回验签结果
***
```c
bool tee_verify(buffer_data *buf_data, int type, char *filename);
```
接口描述：验证报告hash值  
参数1：可信报告缓冲区指针，即事先通过调用QCA_LIB中RemoteAttestReport函数所更新的report参数  
参数2：验证类型，即度量策略，1为仅比对img-hash值，2为仅比对hash值，3为同时比对img-hash和hash两个值  
参数3：基准值文件路径，可从该文件中读取基准值与可信报告中的度量值进行比对  

上述**基准值文件**的**格式要求**：

basevalue文件以十六进制字符串的形式存储基准值记录

每一条basevalue记录分为三项：uuid、image-hash、hash，项与项之间用空格间隔，记录之间用换行间隔

| column | uuid(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) | img-hash | hash |
| --- | --- | --- | --- |
| digit |  (8-4-4-4-12) | 64 | 64 |
| content（e.g.） | B0019DC2-13CD-5A40-99F9-06343DFBE691 | FB4C924ECCE3D00021C97D7FE815F9400AFF90FB84D8A92651CDE3CA2AEB60B1 | 09972A4984CC521651B683B5C85DD9012104A9A57B165B3E26A7A237B7951AD0 |

返回值：验证结果（true or false）
***

>注意：本接口所需入参中验证类型和基准值文件路径都可通过启动客户端时所键入的命令行参数来进行自定义设置

由于**VERIFIER_LIB**是以C语言编写的，因此DEMO程序需要基于CGO机制实现对C接口的调用。

#### AK_Service接口

##### akissuer方法描述

akissuer实现NoDAA/DAA协议帮助生成AK证书。  
akissuer的对外方法如下：
```go
func GenerateAKCert(oldAKCert []byte, scenario int32) ([]byte, error)
```
方法描述：AKS对设备自签名的AK证书进行重新签名。  
参数1：原始AK证书的[]byte值。  
参数2：对应生成AK证书的场景。1 ---> NoDAA证书 ; 2 ---> DAA证书  
返回值1：由AKS重新签名的AK证书[]byte值。  
返回值2：错误输出。
***

##### clientapi方法描述

clientapi接收目标平台AK证书生成请求。  
clientapi的对外方法如下：
```go
func (s *service) GetAKCert(ctx context.Context, in *GetAKCertRequest) (*GetAKCertReply, error)
```
方法描述：gRPC中对应生成指定场景AK证书的服务。  
参数1：服务请求的上下文信息。  
参数2：gRPC请求参数，包含akcert、scenario两个字段。  
返回值1：gRPC响应参数，包含AKS签发的AK证书的字节数组。
返回值2：错误输出。
***
```go
func StartServer(addr string)
```
方法描述：AKS对客户端的服务启动入口。  
参数：AKS服务端的IP:Port地址。
***
```go
func DoGetAKCert(addr string, in *GetAKCertRequest) (*GetAKCertReply, error)
```
方法描述：供外部平台调用的接口，用以获取AKS重新签名的AK证书。  
参数1：待连接服务端的IP:Port地址，这里的服务端即AKS。  
参数2：gRPC请求参数，包含akcert、scenario两个字段。  
返回值1：gRPC响应参数，包含AKS签发的AK证书的字节数组。
返回值2：错误输出。
***

##### config方法描述

AKS的配置服务包，用以获取、修改AKS的指定配置。  
config的对外方法如下：
```go
func InitFlags()
```
方法描述：初始化AKS启动时的命令行参数。  
可用命令行参数如下：
```
-T, --token   为restapi服务生成测试token
```
***
```go
func LoadConfigs()
```
方法描述：加载预定义的配置。  
目前的默认配置为：
```yaml
tasconfig:
  port: 127.0.0.1:40008
  rest: 127.0.0.1:40009
  akskeycertfile: ./ascert.crt
  aksprivkeyfile: ./aspriv.key
  huaweiitcafile: ./Huawei IT Product CA.pem
  DAA_GRP_KEY_SK_X: 65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C
  DAA_GRP_KEY_SK_Y: 126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56
  basevalue: "cc0fe80b4510b3c8d5bf6308024676d2d9e83fbb05ba3d23cd645bfb573ae8a1 bd9df1a7f941c572c14723b80a0fbd805d52641bbac8325681a19d8ba8487b53"
  authkeyfile: ./ecdsakey.pub
```
***
```go
func InitializeAS() error
```
方法描述：对AKS进行初始化。
>本方法主要实现解析AKS的证书、私钥以及解析华为证书的功能，因此要求用户预先在指定路径下配置好相应的AKS证书、AKS私钥以及华为证书，否则AKS将无法正常启动。
***
```go
func GetConfigs() *tasConfig
```
方法描述：获取AKS的所有配置信息。  
返回值：AKS的配置信息。
***
```go
func GetServerPort() string
```
方法描述：获取AKS的clientapi服务端口地址。  
返回值：AKS的clientapi服务端口地址。
***
```go
func GetRestPort() string
```
方法描述：获取AKS的restapi服务端口地址。  
返回值：AKS的restapi服务端口地址。
***
```go
func GetASCertFile() string
```
方法描述：获取AKS证书的文件路径。  
返回值：AKS证书的文件路径。
***
```go
func GetASKeyFile() string
```
方法描述：获取AKS私钥的文件路径。  
返回值：AKS私钥的文件路径。
***
```go
func GetHWCertFile() string
```
方法描述：获取华为证书的文件路径。  
返回值：华为证书的文件路径。
***
```go
func GetASCert() *x509.Certificate
```
方法描述：获取AKS证书。  
返回值：x509格式的AKS证书。
***
```go
func GetASPrivKey() *rsa.PrivateKey
```
方法描述：获取AKS私钥。  
返回值：RSA格式的AKS私钥。
***
```go
func GetHWCert() *x509.Certificate
```
方法描述：获取华为证书。  
返回值：x509格式的华为证书。
***
```go
func GetDAAGrpPrivKey() (string, string)
```
方法描述：获取DAA私钥。  
返回值：DAA私钥X和DAA私钥Y。
***
```go
func GetAuthKeyFile() string
```
方法描述：获取restapi服务的验证密钥文件路径。  
返回值：验证密钥的文件路径。
***
```go
func GetBaseValue() string
```
方法描述：获取对原始AK证书中qta度量数据进行度量的基准值。  
返回值：基准值信息。
***
```go
func SetBaseValue(s string)
```
方法描述：设置对原始AK证书中qta度量数据进行度量的基准值。  
参数：待设置的基准值。
***

##### restapi方法描述

restapi向用户提供信息维护服务。  
restapi的对外方法如下：
```go
func StartServer(addr string)
```
方法描述：AKS对客户端的服务启动入口。  
参数：AKS服务端的IP:Port地址。
***
```go
func CreateTestAuthToken() ([]byte, error)
```
方法描述：生成测试用的token值供用户请求restapi服务时使用。  
返回值1：基于JSON的token值字节数组。  
返回值2：错误输出。
***
```go
func CreateAuthValidator(v JWSValidator) (echo.MiddlewareFunc, error)
```
方法描述：生成restapi服务中对JWT进行验证的中间层。  
返回值1：JWT验证器中间件。  
返回值2：错误输出。
***
```go
func (s *MyRestAPIServer) GetConfig(ctx echo.Context) error
```
方法描述：允许用户读取AKS的配置信息，目前只允许读取基准值。  
参数：请求上下文。    
返回值：错误输出。  
***
```go
func (s *MyRestAPIServer) PostConfig(ctx echo.Context) error
```
方法描述：允许用户修改AKS的配置信息，目前只允许修改基准值。  
参数：请求上下文。  
返回值：错误输出。  
***

### 流程架构图

#### 最小实现

用户可基于TEE Verifier Lib和QCA Lib（由华为对外发布）自行编写TEE Attester来验证TEE中用户TA的完整性，使用TEE自生成的AK。
![tee flow](TEE-flow.png "tee远程证明最小实现原理图")

#### 独立实现

用户可基于TEE Verifier Lib和QCA Lib（由华为对外发布）自行编写TEE Attester来验证TEE中用户TA的完整性，使用TEE AK Service生成AK。

**NO_DAA场景：**
![img](./NoDAA_ak_generate.jpg "有AS无DAA场景下AK生成")

**WITH_DAA场景：**
![img](./DAA_ak_generate.jpg "有AS有DAA场景下AK生成")

#### 整合实现

用户可使用整合在安全库已有远程证明框架中的 TEE/TA 远程证明能力来验证 TEE 中用户 TA 的完整性。
![integrated implementation](./integrated-implementation.png "tee远程证明整合实现软件架构图")
