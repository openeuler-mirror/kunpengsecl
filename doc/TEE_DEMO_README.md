# TEE最小实现

## 设计说明

### 总体方案设计

#### 需求概述
TEE远程证明是鲲鹏安全生态开源组件鲲鹏安全库的一个重要特性，支撑基于鲲鹏平台构建开源机密计算解决方案。

当数据中心管理工具/管理员、云服务基础设施编排工具、密钥管理中心/模型提供方希望获取目标服务器上TEE中TA的可信状态时，需要触发TEE远程证明特性的功能。

本次方案设计基于最小实现场景：用户可基于TEE Verifier Lib和QCA Lib（由华为对外发布）自行编写TEE Attester来验证TEE中用户TA的完整性，使用TEE自生成的AK。

#### 实现原理图
![tee flow](TEE-flow.png "tee远程证明最小实现原理图")

STEP1: 管理员开启服务器。在本方案中服务器是指QCA_DEMO，主要是向客户端提供获取并传输TEE中TA的可信报告的服务；

STEP2: 管理员启动客户端。在本方案中客户端是指ATTESTER_DEMO，管理员可通过指定待验证的TA，设置度量策略、基准值，生成nonce防重放等配置必需的信息入config.yaml文件从而准备好完成验证所必需的条件；

STEP3: ATTESTER_DEMO远程调用QCA_DEMO提供的接口（QAPI）发出获取QTA可信报告的请求，QCA_DEMO在收到请求后，调用QCA_LIB获取QTA的可信报告，再通过QAPI发送给ATTESTER_DEMO，此时可信报告的获取过程结束；

STEP4: ATTESTER_DEMO在收到QCA_DEMO传输回来的可信报告后，将本地调用VERIFIER_LIB提供的可信报告验证接口完成整个验证过程。这一过程主要分为两步，首先是验证nonce、签名、证书等信息，确定生成可信报告的实体身份是否合法，然后根据预先设置的基准值和度量策略，验证可信报告中的度量值是否完整未经篡改，此时可信报告的验证过程结束；

STEP5: 管理员收到ATTESTER_DEMO返回的验证结果，可根据该结果确定TEE中相应的TA是否可信；

### 实体介绍

#### QCA_DEMO介绍
QCA_DEMO在本方案中担任了服务端的角色，主要功能是本地调用QCA_LIB获取TEE中TA的可信报告，然后通过提供一个接口QAPI与位于其他平台的客户端进行交互，传输可信报告。其下分有main.go、qapi.go、qcatools.go三个模块，各自实现不同的功能。另外，由于QCA_DEMO采用Go语言开发，而QCA_LIB采用C语言开发，所以QCA_DEMO同时还借助CGO机制，提供了将C语言编写的可信报告转换为Go语言编写的可信报告的功能。

#### ATTESTER_DEMO介绍
ATTESTER_DEMO在本方案中担任了客户端的角色，主要功能是将从远程获取的TEE中TA的可信报告，本地调用VERIFIER_LIB进行可信验证，包含身份验证和完整性验证，并向管理员返回验证结果。其下分有main.go、attestertools.go两个模块，各自实现不同的功能。另外，由于ATTESTER_DEMO采用Go语言开发，而VERIFIER_LIB采用C语言开发，所以ATTESTER_DEMO同时还借助CGO机制，提供了将Go语言编写的可信报告转换为C语言编写的可信报告的功能。

#### VERIFIER_LIB介绍
VERIFIER_LIB实现TA完整性策略引擎，帮助ATTESTER_DEMO完成TA完整性判定。其下主要分有teeverifier.c、teeverifier.h、common.h三个文件，其中teeverifier.h是teeverifier.c对应的头文件，定义了可向外部暴露的接口，common.h定义了库所用到的各个常量、数据结构、内部函数等，而teeverifier.c则是对外接口的具体功能实现。

#### 实体关系图
![entity relation](TEE-entity-relation.png "tee远程证明最小实现实体关系图")

## 使用手册

### 代码获取
本程序开发基于openEuler系统

首先，您可使用以下命令获取项目最新源代码
```s
git clone https://gitee.com/openeuler/kunpengsecl.git
```
若您尚未安装git工具，可先进行工具安装
```s
sudo yum install git
```
获取源代码后，您需要进入kunpengsecl/目录下执行
```s
git checkout feature/tee-phase1
```
以进入本程序所在分支

### 程序运行

#### 编译
切换分支后，您的kunpengsecl/目录下会出现tee/目录，这是本程序的项目目录。为保证之后程序可以正常运行，请您在该目录下执行
``make build``
实现自动化编译，这需要您事先装有**make**和**gcc**两个工具

若您尚未安装，可通过以下命令进行安装
```s
sudo yum install make gcc
```

在tee/目录下又分为demo/和tverlib/两个子文件夹，tee远程证明的功能实现由tverlib下的代码完成，可以实现对指定可信应用的身份验证和完整性验证；而demo/目录下是一个测试程序，您可以通过该程序查看验证流程

****
当然，您也可以对VERIFIER_LIB进行单独编译（倘若您希望自行实现一个DEMO程序），这需要您进入tee/tverlib/verifier/目录下（这是我们提供TEE远程证明的核心目录），同样执行
``make build``
即可在当前目录编译生成libteeverifier.so动态库文件，另外您可能调用到的头文件都放在本目录下
****

#### 服务端
**QCA_DEMO**是本程序的服务端，主要提供发送指定TA的可信报告的服务，基于Go语言编写。

该实体底层依赖于**QCA_LIB**提供的接口，主要有：
```c
TEEC_Result RemoteAttestProvision(uint32_t scenario, 
                                    struct ra_buffer_data *param_set, 
                                    struct ra_buffer_data *out_data);
```
接口描述：注册并获取AK公钥和证书

参数1【传入】：表示不同的业务场景

scenario=0, 无AS仅有DRK场景

scenario=1, 有AS但无DAA场景

参数2【传入】：属性集

参数3【传出】：输出AK公钥和证书
***
```c
TEEC_Result RemoteAttestReport(TEEC_UUID ta_uuid,
                               struct ra_buffer_data *usr_data,
                               struct ra_buffer_data *param_set,
                               struct ra_buffer_data *report,
                               bool with_tcb);
```
接口描述：获取证明报告

参数1【传入】：待证明的TA uuid

参数2【传入】：用户传入的挑战数据buffer，包括起始地址和大小

参数3【传入】：属性集

参数4【传出】：用户预分配存放证明报告的缓冲区buffer，包括起始地址和大小

参数5【传入】：证明报告是否关联软件可信基度量值
***
```c
TEEC_Result RemoteAttestSaveAKCert(struct ra_buffer_data *akcert);
```
接口描述：保存AK证书

参数1【传入】：证书保存的地址
***
由于**QCA_LIB**是以C语言编写的，因此demo程序需要基于CGO机制实现对C接口的调用，示例如下：
```go
/*
#cgo CFLAGS: -I${BUILD_DIR}
#cgo LDFLAGS: -L${LINK1_DIR} -lqca -Wl,-rpath=${LINK2_DIR}
#include "teeqca.h"
*/
import "C"
```
其中${BUILD_DIR}是指我们的tee verifier库对应头文件的检索路径，这里可以用相对路径

而${LINK1_DIR}是指我们的DEMO程序在**编译**时对动态链接库.so文件的检索路径，这里必须用绝对路径，-lqca说明我们要链接的动态库名称为libqca.so

需要注意的是，${LINK2_DIR}是指我们的DEMO程序在**执行**时对动态链接库.so文件的检索路径，这里也可以用相对路径

***
另外，由于**QCA_LIB**的开发尚未与本项目进行整合，因此我们暂时模拟了一个**QCA_LIB**的实现，其代码放于tee/tverlib/simulator/目录下，相应的DEMO程序代码中对**QCA_LIB**的调用路径也为该目录，进行的是模拟测试，当后期我们与**QCA_LIB**完成整合后，仅需修改以上三个路径变量，即可实现真实的环境测试
***

对于服务端的启用，您可进入kunpengsecl/attestation/tee/demo/qca_demo/cmd/目录下运行
```s
go run main.go
```
读取config.yaml中保存的缺省配置开放服务端口

另外，本程序也支持用户通过命令行键入参数的形式自定义配置，如设置程序的应用场景、指定开放的服务器地址/端口，详细的命令行参数如下：
```
  -C, --scenario int    设置程序的应用场景
  -S, --server string   指定开放的服务器地址/端口
```

#### 客户端
**ATTESTER_DEMO**是本程序的客户端，主要是接收从**QCA_DEMO**处发送过来的可信报告，然后调用**VERIFIER_LIB**提供的接口进行可信验证，返回验证结果给用户，同样基于Go语言编写。

该实体底层依赖于**VERIFIER_LIB**提供的接口，主要有：
***
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
本接口内部由以下三个函数实现对应功能：
***
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
接口描述：验证报告签名和证书有效性
包括例如使用DRK证书对签名数据进行验签(noas)

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

1.通过传入的缓冲区类型的report解析出对应的结构体类型的报告

2.使用DRK证书对sign_drk进行验签（noas情况）

3.从akcert中获取akpub对sign_ak进行验签

4.返回验签结果
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

**注意：本接口所需入参中验证类型和基准值文件路径都可通过启动客户端时所键入的命令行参数来进行自定义设置**

由于**VERIFIER_LIB**是以C语言编写的，因此demo程序需要基于CGO机制实现对C接口的调用

对于客户端的启用，您可进入kunpengsecl/attestation/tee/demo/attester_demo/cmd/目录下运行
```s
go run main.go -T
```
读取config.yaml中保存的缺省配置实现可信验证

**注意：这里必须加`-T`或`--test`参数，因为目前的QCA_LIB为模拟实现，传送过来的是硬编码的可信报告，若不固定nonce值，则验证必然出错**

另外，本程序也支持用户通过命令行键入参数的形式自定义配置，如指定可信应用的UUID、设置基准值文件读取路径、设置度量策略等，详细的命令行参数如下：
```
  -B, --basevalue string   设置基准值文件读取路径
  -M, --mspolicy int       设置度量策略（1为仅比对img-hash值，2为仅比对hash值，3为同时比对img-hash和hash两个值）
  -S, --server string      指定待连接的服务器地址
  -U, --uuid int           指定待验证的可信应用
  -V, --version            打印程序版本并退出
  -T, --test               读取固定的nonce值以匹配目前硬编码的可信报告
```
