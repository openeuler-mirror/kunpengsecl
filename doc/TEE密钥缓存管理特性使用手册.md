# TEE使用文档

<!-- TOC -->

  - [TEE特性实现](#tee特性实现)
      - [密钥缓存管理特性](#密钥缓存管理特性)
          - [准备阶段](#准备阶段)
          - [程序部署](#程序部署)
          - [程序启动](#程序启动)

<!-- TOC -->

## 密钥缓存管理特性

### 准备阶段

本程序开发应用于openEuler系统

首先，从openEuler中获取itrustee_sdk, itrustee_tzdriver, itrustee_client，并将其下载至/root/ 目录下
```bash
$ cd /root/
$ git clone https://gitee.com/openeuler/itrustee_sdk
$ git clone https://gitee.com/openeuler/itrustee_tzdriver
$ git clone https://gitee.com/openeuler/itrustee_client
```

复制itrustee_sdk两份分别命名为itrustee_sdk_for_kta和itrustee_sdk_for_demota
```bash
$ cp -rf itrustee_sdk itrustee_sdk_for_kta
$ cp -rf itrustee_sdk itrustee_sdk_for_demota
```

参考config_cloud.ini中的config与私钥配置文件在上述itrustee_sdk_for_kta与itrustee_sdk_for_demota中进行预先配置

然后，使用以下命令获取项目最新源代码，并将其下载至/root/ 目录下
```bash
$ git clone https://gitee.com/openeuler/kunpengsecl.git
```

若系统尚未安装 `git` 工具，请先进行安装
```bash
$ sudo yum install git
```

### 程序部署

**对于服务端RAS/KCMS，客户端raagent/ka，qca服务的部署**
```bash
$ cd /root/kunpengsecl
#确保ta的证明过程跳过：/root/kunpengsecl/attestation/ras/kcms/kcmstools/kcmstools.go:GetKTATrusted()
$ make clean && make build
$ cp -rf /root/kunpengsecl/attestation/rac/pkg/raagent /usr/bin/raagent
```

**对于demo ca的部署**
```bash
$ cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ca /root/itrustee_sdk_for_demota/test/CA/
#为demo_ca创建新文件
$ cd /root/itrustee_sdk_for_demota/test/CA/demo_ca
$ make
$ cp -f demo_ca /root/vendor/bin
```

**对于demo ta的部署**
```bash
$ cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ta /root/itrustee_sdk_for_demota/test/TA/
$ cp -rf /root/kunpengsecl/attestation/tee/kcml /root/itrustee_sdk_for_demota/test/TA/demo_ta/
#为demo_ta创建新文件
$ cd /root/itrustee_sdk_for_demota/test/TA/demo_ta
$ make
$ cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/ bbb2d138-ee21-43af-8796-40c20d7b45fa.sec /root/data
```

**对于demo kta的部署**
```bash
$ cp -rf /root/kunpengsecl/attestation/tee/kta /root/itrustee_sdk_for_kta/test/TA/
#为kta创建新文件
$ cd /root/itrustee_sdk_for_kta/test/TA/kt
$ make
$ cp -f /root/itrustee_sdk_for_kta/test/TA/kta/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec /root/data
```

执行**quick-scripts**目录下的 `clear-database.sh`与`prepare-kcm-env.sh`脚本准备数据库和kcm使用环境
```bash
$ cd kunpengsecl/attestation/quick-scripts
$ bash clear-database.sh
$ bash prepare-kcm-env.sh 
```

### 程序启动

**对于服务端QCA的启用**
```bash
$ cd /root/kunpengsecl/attestation/tee/demo/qca_demo/cmd/
$ /root/kunpengsecl/attestation/tee/demo/pkg/qcaserver
```

**对于服务端RAS、KCMS的启用**
```bash
$ cd /root/kunpengsecl/attestation/ras/cmd/
$ /root/kunpengsecl/attestation/ras/pkg/ras -T
$ /root/kunpengsecl/attestation/ras/pkg/ras
```

**对于客户端raagent、kta的启用**
```bash
$ cd /root/kunpengsecl/attestation/rac/cmd/raagent
$ git checkout config.yaml
$ /usr/bin/raagent -t -v -k -S
$ /usr/bin/raagent -t -v -k
```

**对于demo_ca、demo_ta的启用**
```bash
$ cd /root/kunpengsecl/attestation/tee/demo/demo_ca
$ /root/vendor/bin/demo_ca
```

### 特性使用命令汇总
#### 代码同步过程
```bash
$ cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ca /root/itrustee_sdk_for_demota/test/CA/
$ cp -rf /root/kunpengsecl/attestation/tee/demo/demo_ta /root/itrustee_sdk_for_demota/test/TA/
$ cp -rf /root/kunpengsecl/attestation/tee/kcml /root/itrustee_sdk_for_demota/test/TA/demo_ta/
$ cp -rf /root/kunpengsecl/attestation/tee/kta /root/itrustee_sdk_for_kta/test/TA/

$ cp -f /root/itrustee_sdk_for_demota/test/CA/demo_ca/* /root/kunpengsecl/attestation/tee/demo/demo_ca/
$ cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/* /root/kunpengsecl/attestation/tee/demo/demo_ta/ 
$ cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/kcml/* /root/kunpengsecl/attestation/tee/kcml/ 
$ cp -f /root/itrustee_sdk_for_kta/test/TA/kta/* /root/kunpengsecl/attestation/tee/kta/
```
#### 构建和部署
```bash
$ cd /root/kunpengsecl && make clean
$ make build
$ cp -f /root/kunpengsecl/attestation/rac/pkg/raagent /usr/bin/raagent
$ cd /root/itrustee_sdk_for_demota/test/CA/demo_ca && make && cp -f demo_ca /root/vendor/bin
$ cd /root/itrustee_sdk_for_demota/test/TA/demo_ta && make && cp -f /root/itrustee_sdk_for_demota/test/TA/demo_ta/ bbb2d138-ee21-43af-8796-40c20d7b45fa.sec /root/data
$ cd /root/itrustee_sdk_for_kta/test/TA/kta && make && cp -f /root/itrustee_sdk_for_kta/test/TA/kta/435dcafa-0029-4d53-97e8-a7a13a80c82e.sec /root/data
```
#### 启动
```bash
cd /root/kunpengsecl/attestation/quick-scripts/ && bash clear-database.sh && bash prepare-kcm-env.sh
$ make build
$ cd /root/kunpengsecl/attestation/ras/cmd/ && /root/kunpengsecl/attestation/ras/pkg/ras -T && /root/kunpengsecl/attestation/ras/pkg/ras -v
$ cd /root/kunpengsecl/attestation/tee/demo/qca_demo/cmd/ && /root/kunpengsecl/attestation/tee/demo/pkg/qcaserver
$ cd /root/kunpengsecl/attestation/rac/cmd/raagent && git checkout config.yaml && rm *.crt && /usr/bin/raagent -t -v -k -S && /usr/bin/raagent -t -v -k435dcafa-0029-4d53-97e8-a7a13a80c82e.sec /root/data
$ cd /root/kunpengsecl/attestation/tee/demo/demo_ca && /root/vendor/bin/demo_ca
```