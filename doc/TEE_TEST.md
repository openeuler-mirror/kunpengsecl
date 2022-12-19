# TEE测试文档

<!-- TOC -->

  - [单元测试](#单元测试)
      - [最小实现](#最小实现)
      - [独立实现](#独立实现)
      - [整合实现](#整合实现)
      - [密钥缓存管理](#密钥缓存管理)
  - [集成测试](#集成测试)
      - [最小实现](#最小实现-1)
      - [独立实现](#独立实现-1)
      - [整合实现](#整合实现-1)
      - [密钥缓存管理](#密钥缓存管理-1)
  - [性能测试](#性能测试)

<!-- TOC -->

## 单元测试

### 最小实现

#### qcatools测试

**覆盖率：** 75.0%  
**测试信息：**  
=== RUN   TestGetTAReport  
2022/12/17 20:50:24 Init qca flags......  
2022/12/17 20:50:24 Load qca Configs......  
2022/12/17 20:50:24 Handle qca flags......  
Get RA_SCENARIO_NO_AS report......  
Get report successfully!  
2022/12/17 20:50:24 Generate TA report succeeded!  
--- PASS: TestGetTAReport (0.00s)  
=== RUN   TestGenerateAKCert  
2022/12/17 20:50:24 Load qca Configs......  
2022/12/17 20:50:24 Handle qca flags......  
Generate AK and AK Cert successfully!  
2022/12/17 20:50:24 NoAS scenario: Generate RSA AK and AK Cert succeeded!  
Generate AK and AK Cert successfully!  
2022/12/17 20:50:24 NoDAA scenario: Generate RSA AK and AK Cert succeeded!  
--- PASS: TestGenerateAKCert (0.00s)  
=== RUN   TestSaveAKCert  
Save AK Cert successfully!  
--- PASS: TestSaveAKCert (0.00s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools  0.004s

#### qapi测试

**覆盖率：** 76.9%  
**测试信息：**  
=== RUN   TestQapi  
2022/12/18 10:59:31 Load TAS configs...  
2022/12/18 10:59:31 Start tee ak server...  
2022/12/18 10:59:31 Init qca flags......  
2022/12/18 10:59:31 Load qca Configs......  
2022/12/18 10:59:31 Start Server......  
2022/12/18 10:59:31 Serve in scenario: RA_SCENARIO_NO_AS  
Generate AK and AK Cert successfully!  
2022/12/18 10:59:31 NoAS scenario: Generate RSA AK and AK Cert succeeded!  
2022/12/18 10:59:32 Client: connect to 127.0.0.1:40007  
2022/12/18 10:59:32 Now have 1 clients connected to server  
Get RA_SCENARIO_NO_AS report......  
Get report successfully!  
2022/12/18 10:59:32 Generate TA report succeeded!  
2022/12/18 10:59:32 Client: connect to 127.0.0.1:40007  
2022/12/18 10:59:32 Now have 2 clients connected to server  
Get RA_SCENARIO_NO_AS report......  
Get report successfully!  
2022/12/18 10:59:32 Generate TA report succeeded!  
2022/12/18 10:59:32 Stop Server......  
2022/12/18 10:59:32 Start Server......  
2022/12/18 10:59:32 Serve in scenario: RA_SCENARIO_AS_NO_DAA  
2022/12/18 10:59:32 AKCert File does not exist!  
Generate AK and AK Cert successfully!  
2022/12/18 10:59:32 NoDAA scenario: Generate RSA AK and AK Cert succeeded!  
2022/12/18 10:59:32 Client: connect to 127.0.0.1:40008  
2022/12/18 10:59:32 Server: Parse drk cert succeeded.  
2022/12/18 10:59:32 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/18 10:59:32 Server: Verify ak signature & QCA ok.  
2022/12/18 10:59:32 Server: re-sign ak cert ok.  
2022/12/18 10:59:32 NoDAA scenario: Generate AK Cert succeeded!  
2022/12/18 10:59:32 Get new cert signed by as succeeded.  
Save AK Cert successfully!  
2022/12/18 10:59:32 Save ak cert into tee.  
2022/12/18 10:59:33 Client: connect to 127.0.0.1:40007  
2022/12/18 10:59:33 Now have 3 clients connected to server  
Get RA_SCENARIO_AS_NO_DAA report......  
Get report successfully!  
2022/12/18 10:59:33 Generate TA report succeeded!  
2022/12/18 10:59:33 Stop Server......  
2022/12/18 10:59:33 Start Server......  
2022/12/18 10:59:33 Serve in scenario: RA_SCENARIO_AS_WITH_DAA  
2022/12/18 10:59:33 AKCert File does not exist!  
Unsupported scenario 2!  
2022/12/18 10:59:33 DAA scenario: Generate AK and AK Cert failed!  
2022/12/18 10:59:34 Client: connect to 127.0.0.1:40007  
2022/12/18 10:59:34 Now have 4 clients connected to server  
bad param_set 4!  
2022/12/18 10:59:34 Get TA report failed!  
--- PASS: TestQapi (3.01s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qapi      3.011s  

#### attestertools测试

**覆盖率：** 71.7%  
**测试信息：**  
=== RUN   TestAttester  
2022/12/19 09:39:09 Load qca Configs......  
2022/12/19 09:39:09 Start Server......  
2022/12/19 09:39:09 Serve in scenario: RA_SCENARIO_NO_AS  
Generate AK and AK Cert successfully!  
2022/12/19 09:39:09 NoAS scenario: Generate RSA AK and AK Cert succeeded!  
2022/12/19 09:39:10 Init attester flags......  
2022/12/19 09:39:10 Load attester Configs......  
2022/12/19 09:39:10 Handle attester flags......  
2022/12/19 09:39:10 Start Attester......  
2022/12/19 09:39:10 127.0.0.1:40007  
2022/12/19 09:39:10 Client: connect to 127.0.0.1:40007  
2022/12/19 09:39:10 Now have 1 clients connected to server  
Get RA_SCENARIO_NO_AS report......  
Get report successfully!  
2022/12/19 09:39:10 Generate TA report succeeded!  
2022/12/19 09:39:10 Get TA report succeeded!  
Couldn't open file: Huawei IT Product CA.pem  
WARNING: failed to verify x509 cert  
Verify success!  
Compare hash measurement..  
Finish Comparation  
2022/12/19 09:39:10 tee verify succeeded!  
2022/12/19 09:39:10 Stop Attester......  
--- PASS: TestAttester (1.00s)  
2022/12/19 09:39:10 Stop Server......  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tee/demo/attester_demo/attestertools        1.006s  

#### verifier lib测试

**覆盖率：** 80%
**测试信息：**
=== NoAS Case ===
nonce:challenge
uuid:
B0019DC213CD5A4099F906343DFBE691
scenario:0
img_hash:
090B10A2DF8CDBDB10509615C83F447F35579D2FE1C632C06BD8CA8C74D069F5

hash:
0F195258B87028A62FB29B1E9EF221897530DC090994E3B17B2350117D259492

reserve:
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

Verify success!
verify signature succeeded
verify nonce succeeded
Compare image & hash measurement..
Finish Comparation
verify succeeded

=== NoDAA Case ===
nonce:challenge
uuid:
04D78FF6B16E144DB218722850EB3EF0
scenario:1
img_hash:
BDA93201BABC6EE96B60EDD6B4104C0A5B2AB66F22B3E82A0FBE121C955755B2

hash:
319964DB5BFAD8FFD1B32ABE7148F7681B1EF15F4BAB8A20D377D9623FEB3758

reserve:
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

Couldn't open file: TAS Root Cert.pem
WARNING: failed to verify x509 cert
Verify success!
verify signature succeeded
verify nonce succeeded
Compare image & hash measurement..
Finish Comparation
verify succeeded

=== DAA Case ===
nonce:challenge
uuid:
B0019DC213CD5A4099F906343DFBE691
scenario:2
img_hash:
0A45C3ABB1F2B3C609645870A9DB35BF6BEBDFC8E822FCF66CE6EBE1E647BE53

hash:
369786D88A4EF603340EB2B98173D1ABEABA5D7205E0ABE4CAC888F2B0ABE663

reserve:
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

Verify success!
verify signature succeeded
verify nonce succeeded
Compare image & hash measurement..
Finish Comparation
verify succeeded
### 独立实现

#### aslib测试

**覆盖率：** 100.0%  
**测试信息：**  
=== RUN   TestGetAKCert  
2022/12/19 10:35:14 Load TAS configs...  
2022/12/19 10:35:14 Start tee ak server...  
2022/12/19 10:35:15 Client: connect to 127.0.0.1:40008  
2022/12/19 10:35:15 Server: Parse drk cert succeeded.  
2022/12/19 10:35:15 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/19 10:35:15 Server: Verify ak signature & QCA ok.  
2022/12/19 10:35:15 Server: re-sign ak cert ok.  
2022/12/19 10:35:15 NoDAA scenario: Generate AK Cert succeeded!  
2022/12/19 10:35:15 Client: connect to 127.0.0.1:40008  
2022/12/19 10:35:15 Server: Parse drk cert succeeded.  
2022/12/19 10:35:15 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/19 10:35:15 Server: Verify ak signature & QCA ok.  
2022/12/19 10:35:15 DAA scenario: Generate AK Cert succeeded!  
2022/12/19 10:35:15 Client: connect to 127.0.0.1:40008  
2022/12/19 10:35:15 Get AKCert failed, error: rpc error: code = Unknown desc = do not need to access as  
--- PASS: TestGetAKCert (1.02s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/aslib     1.027s  

#### akissuer测试

**覆盖率：** 86.6%  
**测试信息：**  
=== RUN   TestGenerateDAAAKCert  
2022/12/17 21:31:19 Load TAS configs...  
2022/12/17 21:31:19 Server: Parse drk cert succeeded.  
2022/12/17 21:31:19 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/17 21:31:19 Server: Verify ak signature & QCA ok.  
--- PASS: TestGenerateDAAAKCert (0.02s)  
=== RUN   TestGenerateNoDAAAKCert  
2022/12/17 21:31:19 Load TAS configs...  
2022/12/17 21:31:19 Server: Parse drk cert succeeded.  
2022/12/17 21:31:19 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/17 21:31:19 Server: Verify ak signature & QCA ok.  
2022/12/17 21:31:19 Server: re-sign ak cert ok.  
--- PASS: TestGenerateNoDAAAKCert (0.02s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tas/akissuer        0.044s  

#### clientapi测试

**覆盖率：** 62.8%  
**测试信息：**  
=== RUN   TestClientapi  
2022/12/19 10:40:07 Load TAS configs...  
2022/12/19 10:40:07 Start tee ak server...  
2022/12/19 10:40:08 Client: connect to 127.0.0.1:40008  
2022/12/19 10:40:08 Server: Parse drk cert succeeded.  
2022/12/19 10:40:08 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/19 10:40:08 Server: Verify ak signature & QCA ok.  
2022/12/19 10:40:08 Server: re-sign ak cert ok.  
2022/12/19 10:40:08 NoDAA scenario: Generate AK Cert succeeded!  
2022/12/19 10:40:08 Client: connect to 127.0.0.1:40008  
2022/12/19 10:40:08 Server: Parse drk cert succeeded.  
2022/12/19 10:40:08 Server: Verify drk signature ok.  
Compare image & hash measurement..  
Finish Comparation  
2022/12/19 10:40:08 Server: Verify ak signature & QCA ok.  
2022/12/19 10:40:08 DAA scenario: Generate AK Cert succeeded!  
2022/12/19 10:40:08 Client: connect to 127.0.0.1:40008  
--- PASS: TestClientapi (1.02s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi       1.028s  

#### config测试

**覆盖率：** 78.9%  
**测试信息：**  
=== RUN   TestConfig  
2022/12/17 21:17:39 Load TAS configs...  
--- PASS: TestConfig (0.00s)  
PASS  
ok      gitee.com/openeuler/kunpengsecl/attestation/tas/config  0.003s

### 整合实现

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

### <a id="最小实现-1"></a>最小实现

测试思路：
1.  Story1.1——Story1.5将一并进行测试。
2.  构建测试目录，并准备必要的文件。
3.  启动QCA服务端。
4.  等待3秒，终止QCA进程。检查是否生成身份密钥和证书，记录检查结果。
5.  先启动QCA服务端，然后添加-T参数启动ATTESTER客户端。
6.  等待3秒，终止QCA进程。检查是否生成指定TA的完整性报告，记录检查结果。
7.  先启动QCA服务端，然后添加-T参数启动ATTESTER客户端。
8.  等待3秒，终止QCA进程。检查ATTESTER是否接收到QCA发送的可信报告，记录检查结果。
9.  先启动QCA服务端，然后添加-T -M 1参数启动ATTESTER客户端。
10. 等待3秒，终止QCA进程。检查ATTESTER是否成功设置可信报告度量策略，记录检查结果。
11. 先启动QCA服务端，然后添加-T参数启动ATTESTER客户端。
12. 等待3秒，终止QCA进程。检查ATTESTER是否成功对可信报告进行验证，记录检查结果。
13. 综合所有检查结果，输出测试成功信息。

测试结果：
>==========  
start integration_test at: 2022年 12月 17日 星期六 15:01:39 CST  
prepare the test environments...  
start qcaserver and generate AK/AKCert...  
end qcaserver...  
已终止  
QTA generate AK/AKCert succeeded!  
start qcaserver and generate TA report...  
start attester...  
end qcaserver...  
已终止  
QTA generate Report succeeded!  
start qcaserver...  
start attester and get TA report...  
end qcaserver...  
已终止  
ATTESTER get Report succeeded!  
start qcaserver...  
start attester and set the measurement policy...  
end qcaserver...  
已终止  
ATTESTER set the measurement policy succeeded!  
start qcaserver...  
start attester and verify TA...  
end qcaserver...  
已终止  
ATTESTER verify TA succeeded!  
test succeeded!  

### <a id="独立实现-1"></a>独立实现

**story2.1测试**

测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，检查QCA测试目录下是否有nodaa-ac.crt文件，若有，则删除。
5. 添加-C 1参数启动QCA Demo。
6. 等待3秒，终止AK Service和QCA Demo进程。
7. 等待3秒，检查AK Service是否有完成QTA完整性度量的日志，若没有，则测试失败，流程结束。
8. 等待3秒，检查QCA测试目录下是否有nodaa-ac.crt文件，若没有，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
.............................................................................................................................................++++  
.....................................................................................................................................................................................................++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.1 at: 2022年 11月 17日 星期四 19:55:28 CST  
prepare the test environments...  
start akservice...  
wait for 3s...  
nodaa-ac.crt is not exist  
test continue...  
start qca demo...  
wait for 3s...  
kill all processes...  
已终止  
已终止  
wait for 3s...  
QTA measurement have been compared  
wait for 3s...  
nodaa-ac.crt generated successed!  
test succeeded!  

**story2.2测试**

测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，检查QCA测试目录下是否有daa-ac.crt文件，若有，则删除。
5. 添加-C 2参数启动QCA Demo。
6. 等待3秒，终止AK Service和QCA Demo进程。
7. 等待3秒，检查AK Service是否有完成QTA完整性度量的日志，若没有，则测试失败，流程结束。
8. 等待3秒，检查QCA测试目录下是否有daa-ac.crt文件，若没有，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
...............++++  
..........++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.2 at: 2022年 11月 17日 星期四 20:21:30 CST  
prepare the test environments...  
start akservice...  
wait for 3s...  
daa-ac.crt is not exist  
test continue...  
start qca demo...  
wait for 3s...  
kill all processes...  
已终止  
已终止  
wait for 3s...  
QTA measurement have been compared  
wait for 3s...  
daa-ac.crt generated successed!  
test succeeded!  

**story2.3测试**

测试思路：
1.  在kunpengsecl根目录下进行 `make build` 编译。
2.  创建测试目录，并加载程序启动所需文件。
3.  添加-T参数启动AK Service获取authtoken值，若获取失败，流程结束。
4.  等待3秒，启动AK Service。
5.  等待3秒，查询当前服务端基准值信息，若查询失败，流程结束，否则，记录为默认基准值。
6.  等待3秒，终止AK Service进程。
7.  等待3秒，重新启动AK Service。
8.  等待3秒，查询当前服务端基准值信息，若与默认值不一致，则测试失败，流程结束。
9.  等待3秒，修改基准值信息为"test value"。
10. 等待3秒，比较修改值是否与"test value"一致，若不一致，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
....................................++++  
..................................................................................................................++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.3 at: 2022年 11月 21日 星期一 10:13:08 CST  
prepare the test environments...  
get authtoken value...  
get authtoken value succeeded  
wait for 3s...  
start akservice...  
wait for 3s...  
get default base value...  
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                 Dload  Upload   Total   Spent    Left  Speed  
100   146  100   146    0     0  16222      0 --:--:-- --:--:-- --:--:-- 16222  
get default base value succeeded  
wait for 3s...  
kill ak service process...  
wait for 3s...  
已终止  
re-start akservice...  
wait for 3s...  
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                 Dload  Upload   Total   Spent    Left  Speed  
100   146  100   146    0     0   142k      0 --:--:-- --:--:-- --:--:--  142k  
check base value is right  
wait for 3s...  
modify base value to: test value  
{"basevalue":"test value"}  
wait for 3s...  
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current  
                                 Dload  Upload   Total   Spent    Left  Speed  
100    27  100    27    0     0  27000      0 --:--:-- --:--:-- --:--:-- 27000  
modify base value to: "test value" succeeded  
test succeeded!  
已终止  

**story2.4测试**

测试思路：
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，添加-C 2参数启动QCA Demo。
5. 等待3秒，检查QCA Demo是否把AK Service签发的AK证书存入TEE侧，若没有，则测试失败，流程结束。
6. 等待3秒，添加-T -U f68fd704-6eb1-4d14-b218-722850eb3ef0参数启动ATTESTER Demo。
7. 等待3秒，终止AK Service、QCA Demo和ATTESTER Demo进程。
8. 等待3秒，检查QCA Demo是否生成给定ID TA的完整性报告，若没有，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
..................................................................................................................................................++++  
.................................................................................................++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.4 at: 2022年 11月 17日 星期四 21:25:38 CST  
prepare the test environments...  
start akservice...  
wait for 3s...  
start qca demo...  
wait for 3s...  
save ak cert into tee succeeded  
wait for 3s...  
start attester demo...  
wait for 3s...  
kill all processes...  
已终止  
已终止  
wait for 3s...  
DAA scenario report is generated for TA:f68fd704-6eb1-4d14-b218-722850eb3ef0  
test succeeded!  

**story2.5测试**

测试思路：
1.  在kunpengsecl根目录下进行 `make build` 编译。
2.  创建测试目录，并加载程序启动所需文件。
3.  启动AK Service。
4.  等待3秒，添加-C 2参数启动QCA Demo。
5.  等待3秒，添加-T -M 1参数启动ATTESTER Demo。
6.  等待3秒，终止ATTESTER Demo进程，检查是否使用度量策略1，若没有，则测试失败，流程结束。
7.  等待3秒，添加-T -M 2参数启动ATTESTER Demo。
8.  等待3秒，终止ATTESTER Demo进程，检查是否使用度量策略2，若没有，则测试失败，流程结束。
9.  等待3秒，添加-T -M 3参数启动ATTESTER Demo。
10. 等待3秒，终止ATTESTER Demo进程，检查是否使用度量策略3，若没有，则测试失败，流程结束。
11. 等待3秒，添加-T -M 0参数启动ATTESTER Demo。
12. 等待3秒，终止AK Service、QCA Demo和ATTESTER Demo进程，检查是否使用度量策略0，若没有，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
.....++++  
......................................................................................................................................................................++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.5 at: 2022年 11月 18日 星期五 10:10:10 CST  
prepare the test environments...  
start akservice...  
wait for 3s...  
start qca demo...  
wait for 3s...  
start attester demo the first time...  
wait for 3s...  
kill attester demo process...  
using measurement policy 1 succeeded  
wait for 3s...  
start attester demo the second time...  
wait for 3s...  
kill attester demo process...  
using measurement policy 2 succeeded  
wait for 3s...  
start attester demo the third time...  
wait for 3s...  
kill attester demo process...  
using measurement policy 3 succeeded  
wait for 3s...  
start attester demo the last time...  
wait for 3s...  
kill all processes...  
已终止  
已终止  
using measurement policy 0 succeeded  
test succeeded!  

**story2.6测试**

测试思路：
1.  在kunpengsecl根目录下进行 `make build` 编译。
2.  创建测试目录，并加载程序启动所需文件。
3.  启动AK Service。
4.  等待3秒，添加-C 2参数启动QCA Demo。
5.  等待3秒，添加-T -M 1参数启动ATTESTER Demo。
6.  等待3秒，终止ATTESTER Demo进程，检查是否完成image度量，若没有，则测试失败，流程结束。
7.  等待3秒，添加-T -M 2参数启动ATTESTER Demo。
8.  等待3秒，终止ATTESTER Demo进程，检查是否完成hash度量，若没有，则测试失败，流程结束。
9.  等待3秒，添加-T -M 3参数启动ATTESTER Demo。
10. 等待3秒，终止ATTESTER Demo进程，检查是否完成image&hash度量，若没有，则测试失败，流程结束。
11. 等待3秒，添加-T -M 0参数启动ATTESTER Demo。
12. 等待3秒，终止AK Service、QCA Demo和ATTESTER Demo进程，检查是否提示度量失败，若没有，则测试失败，流程结束，否则，测试成功。

测试结果：
>~/kunpengsecl ~/kunpengsecl  
Generating RSA private key, 4096 bit long modulus (2 primes)  
.....................................................................................................................................................................................................................................................++++  
.........................++++  
e is 65537 (0x010001)  
writing RSA key  
You are about to be asked to enter information that will be incorporated  
into your certificate request.  
What you are about to enter is what is called a Distinguished Name or a DN.  
There are quite a few fields but you can leave some blank  
For some fields there will be a default value,  
If you enter '.', the field will be left blank.  
\-----  
Country Name (2 letter code) [AU]:  
State or Province Name (full name) [Some-State]:  
Locality Name (eg, city) []:  
Organization Name (eg, company) [Internet Widgits Pty Ltd]:  
Organizational Unit Name (eg, section) []:  
Common Name (e.g. server FQDN or YOUR name) []:  
Email Address []:  
~/kunpengsecl  
\==========  
start story2.6 at: 2022年 11月 18日 星期五 09:53:56 CST  
prepare the test environments...  
start akservice...  
wait for 3s...  
start qca demo...  
wait for 3s...  
start attester demo the first time...  
wait for 3s...  
kill attester demo process...  
measuring image value succeeded  
wait for 3s...  
start attester demo the second time...  
wait for 3s...  
kill attester demo process...  
measuring hash value succeeded  
wait for 3s...  
start attester demo the third time...  
wait for 3s...  
kill attester demo process...  
measuring image & hash value succeeded  
wait for 3s...  
start attester demo the last time...  
wait for 3s...  
kill all processes...  
已终止  
已终止  
check the invalid policy correctly  
test succeeded!  

### <a id="整合实现-1"></a>整合实现

### <a id="密钥缓存管理-1"></a>密钥缓存管理

## 性能测试