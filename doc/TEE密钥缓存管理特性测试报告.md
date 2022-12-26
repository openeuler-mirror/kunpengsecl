# TEE测试文档

<!-- TOC -->

  - [单元测试](#单元测试)
      - [密钥缓存管理](#密钥缓存管理)
          - [kta测试](#kta测试)
          - [katools测试](#katools测试)
          - [kcmtools测试](#kcmstools测试)
          - [kdb测试](#kdb测试)
  - [集成测试](#集成测试)
      - [密钥缓存管理](#密钥缓存管理-1)
  - [性能测试](#性能测试)
      - [密钥缓存管理](#密钥缓存管理-2)
          - [密钥请求响应时间](#密钥请求响应时间)
          - [KA并发支持](#ka并发支持)

<!-- TOC -->

## 单元测试

### 密钥缓存管理

#### kta测试

#### katools测试

**覆盖率：** 12.9%  
**测试信息：**  
=== RUN   TestGetPollDuration  
    config_test.go:51: polldur=3s  
--- PASS: TestGetPollDuration (0.00s)  
=== RUN   TestGetCaCertFile  
    config_test.go:63: caCert=./cert/ca.crt  
--- PASS: TestGetCaCertFile (0.00s)  
=== RUN   TestGetKtaCertFile  
    config_test.go:74: ktaCert=./cert/kta.crt  
--- PASS: TestGetKtaCertFile (0.00s)  
=== RUN   TestGetKtaKeyFile  
    config_test.go:86: ktaCert=./cert/kta.key  
--- PASS: TestGetKtaKeyFile (0.00s)  
=== RUN   TestGetKtaPath  
    config_test.go:97: ktaPath=/root/data/bbb2d138-ee21-43af-8796-40c20d7b45fa.sec  
--- PASS: TestGetKtaPath (0.00s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/rac/ka/katools      0.011s  

#### kcmstools测试

**覆盖率：** 74.0%  
**测试信息：**  
=== RUN   TestDeleteKey  
    kcmstools_test.go:648: delete key information success  
--- PASS: TestDeleteKey (0.00s)  
=== RUN   TestVerifyKTAPubKeyCert  
../cert/kta.crt: OK  
    kcmstools_test.go:670: verify KTAPubKeyCert success  
--- PASS: TestVerifyKTAPubKeyCert (0.01s)  
=== RUN   TestSendKCMPubKeyCert  
    kcmstools_test.go:685: test send kcm public key cert success  
--- PASS: TestSendKCMPubKeyCert (0.00s)  
=== RUN   TestGenerateNewKey  
Start Server...  
    kcmstools_test.go:715: test generate new key success  
--- PASS: TestGenerateNewKey (0.01s)  
=== RUN   TestGetKey  
fail to serve, http: Server closed  
Start Server...  
K: [249 90 41 235 182 50 20 114 120 109 171 173 50 28 195 233 107 95 115 51 225 23 186 89 149 247 59 229 12 167 116 249]   
    kcmstools_test.go:754: test get key success  
--- PASS: TestGetKey (0.01s)  
=== RUN   TestSaveCert  
    kcmstools_test.go:764: test save cert success  
--- PASS: TestSaveCert (0.00s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kcmstools  0.052s  

#### kdb测试

**覆盖率：** 58.5%  
**测试信息：**  
=== RUN   TestSaveKeyInfo  
    kdb_test.go:32: text1  
    kdb_test.go:32: text2  
    kdb_test.go:32: text3  
    kdb_test.go:32: text4  
    kdb_test.go:32: text5  
    kdb_test.go:32: text6  
--- PASS: TestSaveKeyInfo (0.02s)  
=== RUN   TestFindKeyInfo  
    kdb_test.go:54: find key information by taid=1                                    and keyid=testkey1                            , key=&{27 1 testkey1 text1}
--- PASS: TestFindKeyInfo (0.00s)  
=== RUN   TestSavePubKeyInfo  
    kdb_test.go:77: testpubkey1  
    kdb_test.go:77: testpubkey2  
    kdb_test.go:77: testpubkey3  
    kdb_test.go:77: testpubkey4  
    kdb_test.go:77: testpubkey5  
    kdb_test.go:77: testpubkey6  
--- PASS: TestSavePubKeyInfo (0.01s)  
=== RUN   TestFindPubKeyInfo  
    kdb_test.go:98: find public key information by deviceid=1, public   key=&{27 1 testpubkey1}  
--- PASS: TestFindPubKeyInfo (0.00s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/ras/kcms/kdb        0.038s  

## 集成测试

### <a id="密钥缓存管理-1"></a>密钥缓存管理
**story4.1 测试**
测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动RAS。
4. 启动RAC，添加-k 参数启动ka。
5. 等待5秒，检查Initialize KTA success日志是否在echo.txt中存在，若有，则说明测试密钥缓存初始化过程成功，否则，则测试失败，流程结束。
测试结果：
Write out database with 1 new entries
Data Base Updated
~/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at Sun Dec 25 10:43:49 PM CST 2022...
wait for 5s
kill all test processes...
test DONE!!!
count: 1
test succeeded!
**story4.2-3 测试**
测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动RAS。
4. 启动RAC，添加-k 参数启动ka。
5. 等待5秒，检查get TA Trusted success以及get key success日志是否在echo.txt中存在，若有，则说明测试密钥访问鉴权和密钥获取过程成功，否则，则测试失败，流程结束。
测试结果：
Write out database with 1 new entries
Data Base Updated
~/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at Sun Dec 25 11:00:37 PM CST 2022...
wait for 5s
kill all test processes...
test DONE!!!
test get key and verify succeeded!
**story4.4 测试**
测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动RAS。
4. 启动RAC，添加-k 参数启动ka。
5. 等待5秒，检查delete key success日志是否在echo.txt中存在，若有，则说明测试密钥缓存清理过程成功，否则，则测试失败，流程结束。
测试结果：
Write out database with 1 new entries
Data Base Updated
~/go/src/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at 2022年 12月 22日 星期四 21:16:44 CST...
wait for 5s
kill all test processes...
test DONE!!!
count: 0
test delete key succeeded!
**story4.6 测试**  
测试思路：  
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动RAS。
4. 启动RAC，添加-k 参数启动ka。
5. 等待5秒，检查get kta trusted success日志是否在echo.txt中存在，若有，则说明测试密钥缓存初始化过程成功，否则，则测试失败，流程结束。

测试结果：
>start test story4.1 at: Thu 22 Dec 2022 08:39:29 AM PST   
prepare the test environments...   
start test preparation...   
~/gowork/kunpengsecl ~/gowork/kunpengsecl   
clean database   
DROP TABLE client;   
DROP TABLE   
DROP TABLE report;   
DROP TABLE   
DROP TABLE base;   
DROP TABLE   
DROP TABLE tareport;   
DROP TABLE   
DROP TABLE tabase;   
DROP TABLE   
DROP TABLE keyinfo;   
DROP TABLE   
DROP TABLE pubkeyinfo;   
DROP TABLE   
CREATE TABLE   
prepare kcm environment   
Write out database with 1 new entries   
Data Base Updated   
~/gowork/kunpengsecl   
start 1 rac clients at Thu 22 Dec 2022 08:39:54 AM PST...   
wait for 5s   
kill all test processes...   
test DONE!!!   
count: 1   
test get kta trusted success!   

**story4.7 测试**   
测试思路：  
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动RAS。
4. 启动RAC，添加-k 参数启动ka。
5. 等待5秒，检查get kms supported success日志是否在echo.txt中存在，若有，则说明测试密钥缓存初始化过程成功，否则，则测试失败，流程结束。

测试结果：
>start test story4.1 at: Thu 22 Dec 2022 09:04:29 AM PST   
prepare the test environments...   
start test preparation...   
~/gowork/kunpengsecl ~/gowork/kunpengsecl   
clean database   
DROP TABLE client;   
DROP TABLE   
DROP TABLE report;   
DROP TABLE   
DROP TABLE base;   
DROP TABLE   
DROP TABLE tareport;   
DROP TABLE   
DROP TABLE tabase;   
DROP TABLE   
DROP TABLE keyinfo;   
DROP TABLE   
DROP TABLE pubkeyinfo;   
DROP TABLE   
CREATE TABLE   
prepare kcm environment   
Write out database with 1 new entries   
Data Base Updated   
~/gowork/kunpengsecl   
start 1 rac clients at Thu 22 Dec 2022 08:39:54 AM PST...   
wait for 5s   
kill all test processes...   
test DONE!!!   
count: 1   
test get kms supported success!   

## 性能测试

### <a id="密钥缓存管理-2"></a>密钥缓存管理

#### 密钥请求响应时间

**测试目标：** 用户 TA 获取密钥请求响应时间：1.命中：<100ms；2.未命中：<5s

**测试方法：** 先搭建基本测试环境，然后清理数据库，准备必要的KCM私钥/证书等，先后启动RAS、QCA、RAC、DEMO_CA&DEMO_TA，启动结束等待10秒，终止所有RAS/QCA/RAC程序，查看tlogcat输出日志，计算密钥请求/响应的日志时间差，判断是否符合要求。
>注：事先需要手动启动teecd、tlogcat程序

**测试结果：**  
start test tee-test-c at: Mon Dec 26 02:28:27 PM CST 2022  
prepare the test environments...  
start test preparation...  
clean database  
DROP TABLE client;  
DROP TABLE  
DROP TABLE report;  
DROP TABLE  
DROP TABLE base;  
DROP TABLE  
DROP TABLE tareport;  
DROP TABLE  
DROP TABLE tabase;  
DROP TABLE  
DROP TABLE keyinfo;  
DROP TABLE  
DROP TABLE pubkeyinfo;  
DROP TABLE  
CREATE TABLE  
prepare kcm enviroment...  
start ras...  
start qcaserver...  
prepare kcm enviroment...  
start 1 rac clients...  
start demo_ca & demo_ta...  
wait for 10s...  
kill all test processes...  
the time taken when the key is missed is 3004ms  
the time taken when the key is hited is 11ms  
time consumption is acceptable  
test succeeded!  

#### KA并发支持

**测试目标：** KCMS 支持同时连接 KA 数量：>=5000

**测试方法：** 先搭建基本测试环境，然后清理数据库，先后启动一个RAS和QCA程序，接着同时启动5000个RAC，启动结束则等待60秒，终止所有RAS/QCA/RAC程序，读取每个RAC的运行日志，判断是否完成注册。

**测试结果：**  
start test tee-test-c-2 at: Mon Dec 26 04:02:57 AM CST 2022  
prepare the test environments...  
start ka...  
clean database  
DROP TABLE client;  
DROP TABLE  
DROP TABLE report;  
DROP TABLE  
DROP TABLE base;  
DROP TABLE  
DROP TABLE tareport;  
DROP TABLE  
DROP TABLE tabase;  
DROP TABLE  
DROP TABLE keyinfo;  
DROP TABLE  
DROP TABLE pubkeyinfo;  
DROP TABLE  
CREATE TABLE  
start ras...  
start qcaserver and generate AK/AKCert...  
start 5000 rac clients...  
start 100 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 200 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 300 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 400 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 500 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 600 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 700 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 800 rac clients at Mon Dec 26 04:04:50 AM CST 2022...  
start 900 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1000 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1100 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1200 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1300 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1400 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1500 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1600 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1700 rac clients at Mon Dec 26 04:04:51 AM CST 2022...  
start 1800 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 1900 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2000 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2100 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2200 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2300 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2400 rac clients at Mon Dec 26 04:04:52 AM CST 2022...  
start 2500 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 2600 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 2700 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 2800 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 2900 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 3000 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 3100 rac clients at Mon Dec 26 04:04:53 AM CST 2022...  
start 3200 rac clients at Mon Dec 26 04:04:54 AM CST 2022...  
start 3300 rac clients at Mon Dec 26 04:04:54 AM CST 2022...  
start 3400 rac clients at Mon Dec 26 04:04:54 AM CST 2022...  
start 3500 rac clients at Mon Dec 26 04:04:54 AM CST 2022...  
start 3600 rac clients at Mon Dec 26 04:04:55 AM CST 2022...  
start 3700 rac clients at Mon Dec 26 04:04:55 AM CST 2022...  
start 3800 rac clients at Mon Dec 26 04:04:55 AM CST 2022...  
start 3900 rac clients at Mon Dec 26 04:04:56 AM CST 2022...  
start 4000 rac clients at Mon Dec 26 04:04:56 AM CST 2022...  
start 4100 rac clients at Mon Dec 26 04:04:56 AM CST 2022...  
start 4200 rac clients at Mon Dec 26 04:04:56 AM CST 2022...  
start 4300 rac clients at Mon Dec 26 04:04:56 AM CST 2022...  
start 4400 rac clients at Mon Dec 26 04:04:57 AM CST 2022...  
start 4500 rac clients at Mon Dec 26 04:04:57 AM CST 2022...  
start 4600 rac clients at Mon Dec 26 04:04:57 AM CST 2022...  
start 4700 rac clients at Mon Dec 26 04:04:58 AM CST 2022...  
start 4800 rac clients at Mon Dec 26 04:04:59 AM CST 2022...  
start 4900 rac clients at Mon Dec 26 04:04:59 AM CST 2022...  
start 5000 rac clients at Mon Dec 26 04:05:00 AM CST 2022...  
kill all test processes...  
wait for all ka connected...  
test succeeded!  
