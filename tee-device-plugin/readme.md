### 编译设备插件
编译环境要求为arm服务器。更多资料可参考[CA/TA应用运行环境搭建](https://www.hikunpeng.com/document/detail/zh/kunpengcctrustzone/fg-tz/kunpengtrustzone_04_0006.html)
1. 编译工具安装
   ```shell
   yum install go make gcc
   ```
2. 在kunpengsec的同级目录下载itrustee_sdk，
   ```shell
   git clone https://gitee.com/openeuler/itrustee_sdk.git
   ```
3. 准备TA编译，
   ```shell
   mkdir -p kunpengsecl/tee-device-plugin/cmd/TA/TA_cert
   mkdir -p kunpengsecl/tee-device-plugin/cmd/TA/signed_config
   # path/to根据实际情况修改
   cp /path/to/private_key.pem kunpengsecl/tee-device-plugin/cmd/TA/TA_cert
   cp /path/to/config kunpengsecl/tee-device-plugin/cmd/TA/signed_config
   # 根据TA开发者证书的configs.xml修改manifest.txt文件
   vim kunpengsecl/tee-device-plugin/cmd/TA/manifest.txt
   # 根据TA uuid修改CA源代码中TA的uuid
   vim kunpengsecl/tee-device-plugin/cmd/CA/libteememca/tee_mem_ca.c
   ```
4. 进入tee-device-plugin目录，执行make命令，在pkg目录生成插件涉及的文件
   ```shell
   cd kunpengsecl/tee-device-plugin
   make
   ```

### 构建设备插件docker镜像

1. 将程序拷贝到docker目录
   ```shell
   cp pkg/* docker/
   ```
2. 将依赖文件拷贝到docker目录
   ```shell
   cp /usr/bin/tlogcat docker/
   cp /lib/ld-linux-aarch64.so.1 docker/
   cp /usr/lib64/libteec.so docker/
   cp /usr/lib64/libsecurec.so docker/
   ```
3. 构建docker镜像。
   ```shell
   cd docker
   docker build -t tee-device-plugin .
   ```

### 部署插件和TA应用Pod
1. 为支持TrustZone的服务器节点打标签。
   ```shell
   kubectl label nodes <node-name> teetype=trustzone
   ```
2. 部署插件，插件将部署到所有有teetype=trustzone标签的节点
   ```shell
   cd ../deploy
   kubectl create -f tee-device-plugin.yml 
   ```
3. 部署TA应用Pod，客户将TA应用构建为镜像后，按照test-pod.yml创建pod配置文件，执行如下命令完成Pod的自动化部署。
   ```shell
   kubectl create -f test-pod.yml
   ```