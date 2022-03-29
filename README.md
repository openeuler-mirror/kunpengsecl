# 鲲鹏安全库(kunpengsecl)

#### 介绍
本项目开发运行在鲲鹏处理器上的基础安全软件组件，先期主要聚焦在远程证明等可信计算相关领域，使能社区安全开发者。

#### 软件架构
![kunpengsecl arch](doc/RA-arch-1.png "kunpengsecl远程证明架构图")

#### 安装教程

##### 基于Ubuntu系统的安装

首先，您可使用以下命令获取项目最新源代码
```
git clone https://gitee.com/openeuler/kunpengsecl.git
```
若您尚未安装git工具，可通过
```
sudo apt install git
```
进行安装

软件安装前，请执行kunpengsecl/attestation/quick-scripts/目录下的
**prepare-build-env.sh**
脚本准备必需的编译环境

对于服务器RAS和客户端RAC的安装，分别进入kunpengsecl/attestation/ras/和kunpengsecl/attestation/rac/目录下执行
```
make install
```
命令即可自动编译程序并将相应文件安装到缺省位置

另外也支持在kunpengsecl/attestation/目录下执行
```
make install
```
同时安装RAS和RAC

若您需要自定义安装目录，
```
make DESTDIR=/xxx/xxx install(或make install DESTDIR=/xxx/xxx)
```
的指令将很有效

如果出现编译错误，请在kunpengsecl/attestation/目录下运行
```
make vendor
```
命令

卸载方式：

对于服务器RAS和客户端RAC的卸载，分别进入kunpengsecl/attestation/ras/和kunpengsecl/attestation/rac/目录下执行
```
make uninstall
```
命令即可自动清理安装文件

若您此前自定义了安装目录，那么卸载指令的格式则需要更改为
```
make DESTDIR=/xxx/xxx uninstall(或make uninstall DESTDIR=/xxx/xxx)
```

##### 基于openEuler系统的安装

openEuler系统可采用rpm的安装方式，首先，您可使用以下命令获取项目最新源代码
```
git clone https://gitee.com/openeuler/kunpengsecl.git
```
若您尚未安装git工具，可通过
```
sudo yum install git
```
进行安装

软件安装前，请执行kunpengsecl/attestation/quick-scripts/目录下的
**prepare-build-env.sh**
脚本准备必需的编译环境

另外，请确保您已安装好rpm打包工具
**rpmdevtools**
之后在kunpengsecl/目录下执行
```
make rpm
```
即可生成程序的rpm包

之后，您可根据实际需求，选择安装rac或ras对应的rpm包，安装命令如下：
```
sudo rpm -ivh xxx.rpm
```
卸载方式：
```
sudo rpm -e xxx
```
#### 使用说明
在运行本软件前，请进入kunpengsecl/attestation/quick-scripts/目录执行
**prepare-database-env.sh**
脚本以准备必需的数据库环境

##### 服务器方面
于kunpengsecl/attestation/ras/cmd/ras/目录下命令行输入
``ras``
即可开启服务器。相关参数如下：
```
  -p, --port string   this app service listen at [IP]:PORT
  -r, --rest string   this app rest interface listen at [IP]:PORT
  -T, --token         generate test token and quit
  -v, --verbose       show more detail running information
  -V, --version       show version number and quit
```

##### 客户端方面
于kunpengsecl/attestation/rac/cmd/raagent/目录下命令行输入
``sudo raagent``
即可开启客户端（请注意，物理TPM模块的开启需要sudo权限）。相关参数如下：
```
  -s, --server string   connect attestation server at IP:PORT
  -t, --test            run in test mode[true] or not[false/default]
  -v, --verbose         show more detail running information
  -V, --version         show version number and quit
```

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request

