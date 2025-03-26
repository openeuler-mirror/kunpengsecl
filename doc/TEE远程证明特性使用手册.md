# TEE使用文档

<!-- TOC -->

  - [TEE特性实现](#tee特性实现)
      - [远程证明特性](#远程证明特性)
          - [安装部署](#安装部署)
          - [程序启动](#程序启动)
              - [最小实现](#最小实现)
              - [独立实现](#独立实现)
              - [整合实现](#整合实现)

<!-- TOC -->

## 远程证明特性

### 安装部署

本程序开发应用于openEuler系统

首先，使用以下命令获取项目最新源代码

```bash
$ git clone https://gitee.com/openeuler/kunpengsecl.git
```

若系统尚未安装 `git` 工具，请先进行安装

```bash
$ sudo yum install git
```

执行**quick-scripts**目录下的 `prepare-build-env.sh` 脚本准备基本编译环境

```bash
$ cd kunpengsecl/attestation/quick-scripts
$ bash prepare-build-env.sh
```

接着，进入项目根目录进行编译

```bash
$ cd kunpengsecl
$ make build
```

>请注意：示例中使用 `cd` 命令的起始位置皆为程序根目录（kunpengsecl）的上一级目录！

**关于目录结构的说明**

在**tee**目录下又分为**demo**和**tverlib**两个子目录，TEE远程证明的功能实现由**tverlib**下的代码完成，主要包括基于C语言编写的库文件，可以实现对指定可信应用的身份验证和完整性验证；而**demo**目录下是一个测试程序，可通过该程序查看验证流程。

**关于自行实现attester的编译说明**

若用户需要自行实现一个DEMO程序调用TEE远程证明的动态库，可对VERIFIER_LIB进行单独编译

```bash
$ cd kunpengsecl/attestation/tee/tverlib/verifier
$ make build
```

编译后生成libteeverifier.so动态库文件，并存放在**verifier**目录下，另外，该目录也存放着用户可能用到的头文件。

此外，要启用AKS服务，需要先为AKS配置好私钥和证书。

```bash
$ cd kunpengsecl/attestation/tas/cmd
$ openssl genrsa -out aspriv.key 4096
$ openssl req -new -x509 -days 365 -key aspriv.key -out ascert.crt
```

### 程序启动

#### 最小实现

**对于服务端QCA的启用**

```bash
$ cd kunpengsecl/attestation/tee/demo/qca_demo/cmd
$ go run main.go
```

读取 `config.yaml` 中保存的缺省配置开放服务端口。

另外，本程序也支持用户通过命令行键入参数的形式自定义配置，如设置程序的应用场景、指定开放的服务器地址/端口，详细的命令行参数如下：

```text
  -C, --scenario int    设置程序的应用场景
  -S, --server string   指定开放的服务器地址/端口
```

**对于客户端ATTESTER的启用**

```bash
$ cd kunpengsecl/attestation/tee/demo/attester_demo/cmd
$ go run main.go -T
```

读取 `config.yaml` 中保存的缺省配置实现可信验证。

>注意：这里必须加`-T`或`--test`参数，因为目前的QCA_LIB为模拟实现，传送过来的是硬编码的可信报告，若不固定nonce值，则验证必然出错！

另外，本程序也支持用户通过命令行键入参数的形式自定义配置，如指定可信应用的UUID、设置基准值文件读取路径、设置度量策略等，详细的命令行参数如下：

```text
  -B, --basevalue string   设置基准值文件读取路径
  -M, --mspolicy int       设置度量策略（1为仅比对img-hash值，2为仅比对hash值，3为同时比对img-hash和hash两个值）
  -S, --server string      指定待连接的服务器地址
  -U, --uuid int           指定待验证的可信应用
  -V, --version            打印程序版本并退出
  -T, --test               读取固定的nonce值以匹配目前硬编码的可信报告
```

#### 独立实现

**1. No-DAA 场景**
**对于证明密钥服务端AK_Service的启用**

要启用AKS服务，需要先为AKS配置好私钥和证书。

```bash
$ cd kunpengsecl/attestation/tas/cmd
$ openssl genrsa -out aspriv.key 4096
$ openssl req -new -x509 -days 365 -key aspriv.key -out ascert.crt
$ go run main.go
```

读取 `config.yaml` 中保存的缺省配置开放服务端口，加载设备证书和根证书，配置DAA密钥等。

**对于服务端QCA的启用**

```bash
$ cd kunpengsecl/attestation/tee/demo/qca_demo/cmd
$ go run main.go -C 1
```

读取 `config.yaml` 中保存的缺省配置开放服务端口。

**对于ATTESTER的启用**

同<a href="#程序启动">最小实现</a>。

>注：在有AK_Service环境中，为提高QCA配置证书的效率，并非每一次启动都需要访问AK_Service以生成相应证书，而是通过证书的本地化存储，即读取QCA侧 `config.yaml` 中配置的证书路径，通过 `func hasAKCert(s int) bool` 函数检查是否已有AK_Service签发的证书保存于本地，若成功读取证书，则无需访问AK_Service，若读取证书失败，则需要访问AK_Service，并将AK_Service返回的证书保存于本地。

**2. DAA 场景**
**对于证明密钥服务端AK_Service的启用**

要启用AKS服务，需要先为AKS配置好私钥。

```bash
$ cd kunpengsecl/attestation/tas/cmd
$ vim config.yaml
 # 如下DAA_GRP_KEY_SK_X和DAA_GRP_KEY_SK_Y的值仅用于测试，正常使用前请务必更新其内容以保证安全。
tasconfig:
  port: 127.0.0.1:40008
  rest: 127.0.0.1:40009
  akskeycertfile: ./ascert.crt
  aksprivkeyfile: ./aspriv.key
  huaweiitcafile: ./Huawei IT Product CA.pem
  DAA_GRP_KEY_SK_X: 65A9BF91AC8832379FF04DD2C6DEF16D48A56BE244F6E19274E97881A776543C
  DAA_GRP_KEY_SK_Y: 126F74258BB0CECA2AE7522C51825F980549EC1EF24F81D189D17E38F1773B56
$ go run main.go
```

读取 `config.yaml` 中保存的缺省配置开放服务端口，加载设备证书和根证书，配置DAA密钥等。

**对于服务端QCA的启用**

```bash
$ cd kunpengsecl/attestation/tee/demo/qca_demo/cmd
$ go run main.go -C 2
```

读取 `config.yaml` 中保存的缺省配置开放服务端口。

**对于ATTESTER的启用**

同<a href="#程序启动">最小实现</a>。

>注：在有AK_Service环境中，为提高QCA配置证书的效率，并非每一次启动都需要访问AK_Service以生成相应证书，而是通过证书的本地化存储，即读取QCA侧 `config.yaml` 中配置的证书路径，通过 `func hasAKCert(s int) bool` 函数检查是否已有AK_Service签发的证书保存于本地，若成功读取证书，则无需访问AK_Service，若读取证书失败，则需要访问AK_Service，并将AK_Service返回的证书保存于本地。

目前，在AKS端，为支持管理员的远程控制，提供了以下接口可使用：

```text
/config: GET
/config: POST
```

若管理员需要查询AKS端的配置信息，可使用`/config`接口的GET方法：

```shell
curl -X GET -H "Content-Type: application/json" http://localhost:40009/config
```

***
若管理员需要修改AKS端的配置信息，可使用`/config`接口的POST方法：

```shell
curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -d '{"basevalue":"testvalue"}' http://localhost:40009/config
```

>注：AKS端的配置信息读取与修改目前仅支持基准值

#### 整合实现

##### RAS启动参数

命令行输入`ras`即可启动RAS程序。在RAS目录下需要提供`ECDSA`公钥并命名为`ecdsakey.pub`。相关参数如下：

```text
  -H  --https         http/https模式开关，默认为https(true)，false=http
  -h  --hport         https模式下RAS监听的restful api端口
  -p, --port string   RAS监听的client api端口
  -r, --rest string   http模式下RAS监听的restful api端口
  -T, --token         生成一个测试用的验证码并退出
  -v, --verbose       打印更详细的RAS运行时日志信息
  -V, --version       打印RAS版本并退出
```

##### RAC启动参数

命令行输入`sudo raagent`即可启动RAC程序，请注意，物理TPM模块的开启需要sudo权限。相关参数如下：

```text
  -s, --server string   指定待连接的RAS服务端口
  -t, --test            true=以测试模式启动，false=以正常模式启动
  -v, --verbose         打印更详细的RAC运行时日志信息
  -V, --version         打印RAC版本并退出
  -i, --imalog          指定ima文件路径
  -b, --bioslog         指定bios文件路径
  -T, --tatest          true=以TA测试模式启动，false=以正常模式启动
```

##### 接口定义

为了便于管理员对目标服务器上部署的TEE中的用户 TA 进行管理，本程序设计了以下接口可供调用：

```bash
/{id}/ta/{tauuid}/status: GET
/{id}/ta/{tauuid}/tabasevalues: GET
/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}: GET、POST、DELETE
/{id}/ta/{tauuid}/newtabasevalue: POST
/{id}/ta/{tauuid}/tareports: GET
/{id}/ta/{tauuid}/tareports/{tareportid}: GET、DELETE
```

接下来分别介绍上述接口的具体用法。

***

若您想要查询目标服务器上特定用户 TA 的可信状态，那么您可以使用`"/{id}/ta/{tauuid}/status"`接口的GET方法。其中$AUTHTOKEN是您事先使用`ras -T`自动生成的身份验证码，{id}是RAS为目标服务器分配的唯一标识号，{tauuid}是特定用户 TA 的身份标识号。

```bash
$ curl -k -X GET -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" https://localhost:40003/{id}/ta/{tauuid}/status
```

***
若您想要查询目标服务器上特定用户 TA 的所有基准值信息，那么您可以使用`"/{id}/ta/{tauuid}/tabasevalues"`接口的GET方法。

```bash
$ curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/ta/{tauuid}/tabasevalues
```

***
若您想要查询目标服务器上特定用户 TA 的指定基准值的详细信息，那么您可以使用`"/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}"`接口的GET方法。其中{tabasevalueid}是RAS为目标服务器上特定用户 TA 的指定基准值分配的唯一标识号。

```bash
$ curl -k -X GET -H "Content-type: application/json" https://localhost:40003/{id}/ta/{tauuid}/tabasevalues{tabasevalueid}
```

***
若您想要修改目标服务器上特定用户 TA 的指定基准值的可用状态，那么您可以使用`"/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}"`接口的`POST`方法。

```bash
$ curl -k -X POST -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN"  https://localhost:40003/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid} --data '{"enabled":true}'
```

***
若您想要删除目标服务器上特定用户 TA 的指定基准值，那么您可以使用`"/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}"`接口的`DELETE`方法，注意，使用该方法将删除指定基准值的所有信息，您将无法再通过接口对该基准值进行查询！

```bash
$ curl -X DELETE -H "Content-type: application/json" -H "Authorization: $AUTHTOKEN" -k http://localhost:40003/{id}/ta/{tauuid}/tabasevalues/{tabasevalueid}
```

***
若您想要给目标服务器上特定用户 TA 新增一条基准值信息，那么您可以使用`"/{id}/ta/{tauuid}/newtabasevalue"`接口的`POST`方法。

```go
type tabaseValueJson struct {
    Uuid      string `json:"uuid"`       // 用户 TA 的标识号
    Name      string `json:"name"`       // 基准值名称
    Enabled   bool   `json:"enabled"`    // 基准值是否可用
    Valueinfo string `json:"valueinfo"`  // 镜像哈希值和内存哈希值
}
```

```bash
$ curl -X POST -H "Content-Type: application/json" -H "Authorization: $AUTHTOKEN" -k https://localhost:40003/24/ta/test/newtabasevalue -d '{"uuid":"test", "name":"testname", "enabled":true, "valueinfo":"test info"}'
```

***
若您想要查询目标服务器上特定用户 TA 的所有可信报告，那么您可以使用`"/{id}/ta/{tauuid}/tareports"`接口的`GET`方法。

```bash
$ curl -k -X GET -H "Content-type: application/json" https://localhost:40003/28/ta/test/tareports
```

***
若您想要查询目标服务器上特定用户 TA 的指定可信报告的详细信息，那么您可以使用`"/{id}/ta/{tauuid}/tareports/{tareportid}"`接口的`GET`方法，其中{tareportid}是RAS为目标服务器上特定用户 TA 的指定可信报告分配的唯一标识号。

```bash
$ curl -k -X GET -H "Content-type: application/json" https://localhost:40003/28/ta/test/tareports/2
```

***
若您想要删除目标服务器上特定用户 TA 的指定可信报告，那么您可以使用`"/{id}/ta/{tauuid}/tareports/{tareportid}"`接口的`DELETE`方法，注意，使用该方法将删除指定可信报告的所有信息，您将无法再通过接口对该报告进行查询！

```bash
$ curl -X DELETE -H "Content-type: application/json" http://localhost:40003/28/ta/test/tareports/2
```
