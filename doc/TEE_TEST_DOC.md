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
      - [最小实现/独立实现](#最小实现独立实现)
      - [整合实现](#整合实现-2)
      - [密钥缓存管理](#密钥缓存管理-2)

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

#### RAC测试

##### ractools测试

**覆盖率：** 51.3%  
**测试信息：**  
=== RUN   TestOpenSWTPM  
--- PASS: TestOpenSWTPM (0.00s)  
=== RUN   TestSetDigestAlg  
--- PASS: TestSetDigestAlg (0.06s)  
=== RUN   TestCreateTrustReport  
--- PASS: TestCreateTrustReport (0.10s)  
=== RUN   TestNVRAM  
--- PASS: TestNVRAM (0.14s)  
=== RUN   TestActivateIKCert  
--- PASS: TestActivateIKCert (0.24s)  
PASS  
coverage: 51.3% of statements in ./  
ok      gitee.com/openeuler/kunpengsecl/attestation/rac/ractools        0.553s  

#### RAS测试

##### cache测试

**覆盖率：** 72.9%  
**测试信息：**  
== RUN   TestHeartBeat  
--- PASS: TestHeartBeat (6.02s)  
=== RUN   TestUpdateTrustReport  
--- PASS: TestUpdateTrustReport (0.00s)  
=== RUN   TestOnline  
--- PASS: TestOnline (8.02s)  
=== RUN   TestCommands  
--- PASS: TestCommands (0.00s)  
=== RUN   TestTrusted  
--- PASS: TestTrusted (0.00s)  
=== RUN   TestNonce  
--- PASS: TestNonce (0.00s)  
=== RUN   TestIKeyCert  
--- PASS: TestIKeyCert (0.00s)  
=== RUN   TestRegTime  
--- PASS: TestRegTime (0.00s)  
=== RUN   TestIsAutoUpdate  
--- PASS: TestIsAutoUpdate (0.00s)  
PASS  
coverage: 72.9% of statements in ./  
ok      gitee.com/openeuler/kunpengsecl/attestation/ras/cache   14.048s  

##### config测试

**覆盖率：** 60.8%  
**测试信息：**  
=== RUN   TestRASConfig1  
--- PASS: TestRASConfig1 (2.03s)  
=== RUN   TestRASConfig2  
{{[1 2 3 4]} [{bios [8-0 80000008-1]} {ima [boot_aggregate /etc/modprobe.d/tuned.conf]}]}  
--- PASS: TestRASConfig2 (0.00s)  
=== RUN   TestRACConfig  
--- PASS: TestRACConfig (0.01s)  
PASS  
coverage: 60.8% of statements in ./  
ok      gitee.com/openeuler/kunpengsecl/attestation/ras/config  2.059s  

##### trustmgr测试

**覆盖率：** 23.0%  
**测试信息：**  
=== RUN   TestRegisterClient  
--- PASS: TestRegisterClient (0.16s)  
=== RUN   TestFindClient  
    trustmgr_test.go:498: find client by ik=IK22-12-19-20-34-10KA, c=&{26 2022-12-19 20:34:10.393153 +0800 CST true {"ip": "8.8.8.10", "last": 10, "name": "google DNS"} IK22-12-19-20-34-10KA}  
    trustmgr_test.go:504: find client by id=26, c=&{26 2022-12-19 20:34:10.393153 +0800 CST true {"ip": "8.8.8.10", "last": 10, "name": "google DNS"} IK22-12-19-20-34-10KA}  
    trustmgr_test.go:511: find client by info={"name": "google DNS"}  
    trustmgr_test.go:513:   0, {26 2022-12-19 20:34:10.393153 +0800 CST true {"ip": "8.8.8.10", "last": 10, "name": "google DNS"}IK22-12-19-20-34-10KA}  
--- PASS: TestFindClient (0.03s)  
=== RUN   TestReport  
--- PASS: TestReport (0.06s)  
=== RUN   TestBaseValue  
--- PASS: TestBaseValue (0.04s)  
=== RUN   TestTaBaseValue  
--- PASS: TestTaBaseValue (0.04s)  
=== RUN   TestTaReport  
--- PASS: TestTaReport (0.04s)  
PASS  
coverage: 23.0% of statements in ./  
ok      gitee.com/openeuler/kunpengsecl/attestation/ras/trustmgr        0.393s  

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

测试思路：
1. 配置好raagent和ras的配置文件，ras使用缺省ras配置文件（mgrstrategy: auto），raagent使用缺省rac配置文件（clientID: -1）；
2. 清空kunpengsecl所有数据库表；
3. 分别启动ras和raagent（仅一个raagent，-t 测试模式启动）；
4. 等待20s，向restapi发送请求获取当前TA完整性验证策略，记录restapi的响应；
5. 向restapi发送请求修改TA完整性验证策略，记录restapi的响应；
6. 等待120s，向restapi发送请求获取当前TA可信报告，记录restapi的响应；
7. 终止ras和raagent进程；
8. 检查前两次restapi的响应，确认第一次响应包含一个TA验证策略条目，条目中的策略值为3，第二次响应也包含一个TA验证策略条目，但条目中的策略值为1；
9. 检查第三次restapi的响应，确认包含一个TA可信报告完整性验证信息条目，条目中的值为true；同时包含一个TA可信状态信息条目，条目中的可信状态为true。

测试结果：
==========
start test tee-phase3 at: 2022年 12月 22日 星期四 16:02:42 CST
prepare the test environments...
start test preparation...
~/goProject/src/gitee.com/openeuler/kunpengsecl ~/goProject/src/gitee.com/openeuler/kunpengsecl
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
~/goProject/src/gitee.com/openeuler/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at 2022年 12月 22日 星期四 16:02:43 CST...
start to perform test ...
wait for 20s
get client id
1
modify ta verify type via restapi request
step1: get current ta verify type via restapi request
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   362  100   362    0     0  77037      0 --:--:-- --:--:-- --:--:-- 90500
{"hbduration":"10s","trustduration":"2m0s","isallupdate":false,"logtestmode":true,"digestalgorithm":"sha1","mgrstrategy":"auto","extractrules":"{\"PcrRule\":{\"PcrSelection\":[1,2,3,4]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-1\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\",\"/etc/modprobe.d/tuned.conf\"]}]}","taverifytype":3}
step2: set new ta verify type via restapi request
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   381  100   362  100    19  28673   1504 --:--:-- --:--:-- --:--:-- 29307
{"hbduration":"10s","trustduration":"2m0s","isallupdate":false,"logtestmode":true,"digestalgorithm":"sha1","mgrstrategy":"auto","extractrules":"{\"PcrRule\":{\"PcrSelection\":[1,2,3,4]},\"ManifestRules\":[{\"MType\":\"bios\",\"Name\":[\"8-0\",\"80000008-1\"]},{\"MType\":\"ima\",\"Name\":[\"boot_aggregate\",\"/etc/modprobe.d/tuned.conf\"]}]}","taverifytype":1}
verify ta to get trust status via restapi request
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   381  100   362  100    19  75653   3970 --:--:-- --:--:-- --:--:-- 95250
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   130  100   130    0     0  21392      0 --:--:-- --:--:-- --:--:-- 26000
[{"ID":1,"ClientID":1,"CreateTime":"2022-12-22T16:02:44.51073+08:00","Validated":true,"Trusted":true,"Uuid":"test","Value":null}]
kill all test processes...
test DONE!!!
ClientID:1
TAVerifyType1: 3  TAVerifyType2: 1
Validated: true,  Status2: true,
test succeeded!

### <a id="密钥缓存管理-1"></a>密钥缓存管理

## 性能测试

### 最小实现/独立实现

#### ATTESTER并发支持

**测试目标：** QCA 支持的同时连接的 TEE Attester 数目： >=10

**测试方法：** 搭建基本测试环境，先启动QCA，接着同时启动10个Attester，启动结束后等待1秒，终止所有QCA/Attester程序，依次查看每个Attester的运行日志，判断是否都能成功从QCA获取到可信报告。

**测试结果：**  
start test tee-test-a at: Thu Dec 22 04:14:25 AM CST 2022  
prepare the test environments...  
start qcaserver and generate AK/AKCert...  
start 10 attester...  
start 10 attester at Thu Dec 22 04:14:25 AM CST 2022...  
kill all processes  
wait for all attester get report...  
test succeeded!  

#### QCA并发支持

**测试目标：** TAS 支持的同时连接的最大 QCA 数目： >=5000

**测试方法：** 搭建基本测试环境，先启动TAS，接着同时启动5000个QCA，启动结束后等待1秒，终止所有TAS/QCA程序，依次查看每个QCA的运行日志，判断是否都能从TAS获取AK证书。

**测试结果：**  
start test tee-test-a at: Thu Dec 22 04:26:31 AM CST 2022  
prepare the test environments...  
start akservice...  
start 5000 qca...  
start 100 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 200 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 300 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 400 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 500 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 600 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 700 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 800 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 900 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 1000 qca at Thu Dec 22 04:27:20 AM CST 2022...  
start 1100 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1200 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1300 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1400 qca at Thu Dec 22 04:27:21 AM CST 2022...   
start 1500 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1600 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1700 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1800 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 1900 qca at Thu Dec 22 04:27:21 AM CST 2022...  
start 2000 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2100 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2200 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2300 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2400 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2500 qca at Thu Dec 22 04:27:22 AM CST 2022...  
start 2600 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 2700 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 2800 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 2900 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 3000 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 3100 qca at Thu Dec 22 04:27:23 AM CST 2022...  
start 3200 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3300 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3400 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3500 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3600 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3700 qca at Thu Dec 22 04:27:24 AM CST 2022...  
start 3800 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 3900 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 4000 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 4100 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 4200 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 4300 qca at Thu Dec 22 04:27:25 AM CST 2022...  
start 4400 qca at Thu Dec 22 04:27:26 AM CST 2022...  
start 4500 qca at Thu Dec 22 04:27:26 AM CST 2022...  
start 4600 qca at Thu Dec 22 04:27:26 AM CST 2022...  
start 4700 qca at Thu Dec 22 04:27:26 AM CST 2022...  
start 4800 qca at Thu Dec 22 04:27:26 AM CST 2022...  
start 4900 qca at Thu Dec 22 04:27:27 AM CST 2022...  
start 5000 qca at Thu Dec 22 04:27:27 AM CST 2022...  
kill all processes  
wait for all qca get ak cert...  
test succeeded!  

#### TA并发支持

**测试目标：** TEE Verifier Lib 支持的 TA 数目： >=5000

**测试方法：**

**测试结果：**

### <a id="整合实现-2"></a>整合实现

#### RAC并发支持

**测试目标：** 支持同时连接 RAC 的数量 >= 5000

**测试方法：** 先搭建基本测试环境，然后清理数据库，先后启动一个RAS和QCA程序，接着同时启动5000个RAC，启动结束则等待1秒，终止所有RAS/QCA/RAC程序，读取每个RAC的运行日志，判断是否完成注册。

**测试结果：**

#### RestAPI单个查询

**测试目标：** RestAPI 单次调用查询 1 个目标服务器可信状态的时间平均 <= 1s， 最长 <= 5s

**测试方法：** 先搭建基本测试环境，然后清理数据库，先后启动一个RAS和QCA程序，接着同时启动1个RAC，启动结束等待20秒，然后调用RestAPI查询 1 个目标服务器可信状态，反复调用10000次，记录每次查询所用时间，最后计算出平均查询时间和最大查询时间。查看control.txt内的返回信息，判断是否正确获取到可信状态。

**测试结果：**
start test tee-test-b-2 at: 2022年 12月 22日 星期四 17:29:11 CST  
prepare the test environments...  
start test preparation...  
~/go/src/gitee.com/openeuler/kunpengsecl ~/go/src/gitee.com/openeuler/kunpengsecl  
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
~/go/src/gitee.com/openeuler/kunpengsecl  
start ras...  
start qcaserver...  
start 1 rac clients...  
start 1 rac clients at 2022年 12月 22日 星期四 17:29:12 CST...  
start to perform test ...  
wait for 20s  
get client id  
1  
get 10000 times server trust status via restapi request  
change MAXTIME=30ms  
change MAXTIME=39ms  
change MAXTIME=42ms  
change MAXTIME=61ms  
change MAXTIME=162ms  
It took 243216ms to get 10000 times trust status of 1 server, the average time is 24ms, the max time is 162ms.  
kill all test processes...  
已终止  
test DONE!!!  

#### RestAPI千个查询

**测试目标：** RestAPI 单次调用查询 1000 个目标服务器可信状态的时间平均 <= 5s， 最长 <= 10s

**测试方法：** 

**测试结果：**

### <a id="密钥缓存管理-2"></a>密钥缓存管理
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
~/go/src/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at 2022年 12月 22日 星期四 21:14:13 CST...
wait for 5s
kill all test processes...
test DONE!!!
count: 0
test KTA Initialize succeeded!
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
~/go/src/kunpengsecl
start ras...
start 1 rac clients...
start 1 rac clients at 2022年 12月 22日 星期四 21:14:48 CST...
wait for 5s
kill all test processes...
test DONE!!!
count1: 0
count2: 0
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
#### 密钥请求响应时间

**测试目标：** 用户 TA 获取密钥请求响应时间：1.命中：<100ms；2.未命中：<5s

**测试方法：** 

**测试结果：**

#### KA并发支持

**测试目标：** KCMS 支持同时连接 KA 数量：>=5000

**测试方法：** 

**测试结果：**