# 独立实现测试

## story2.1测试

### 测试思路
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，检查QCA测试目录下是否有nodaa-ac.crt文件，若有，则删除。
5. 添加-C 1参数启动QCA Demo。
6. 等待3秒，终止AK Service和QCA Demo进程。
7. 等待3秒，检查AK Service是否有完成QTA完整性度量的日志，若没有，则测试失败，流程结束。
8. 等待3秒，检查QCA测试目录下是否有nodaa-ac.crt文件，若没有，则测试失败，流程结束，否则，测试成功。

### 测试结果
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

## story2.2测试

### 测试思路
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，检查QCA测试目录下是否有daa-ac.crt文件，若有，则删除。
5. 添加-C 2参数启动QCA Demo。
6. 等待3秒，终止AK Service和QCA Demo进程。
7. 等待3秒，检查AK Service是否有完成QTA完整性度量的日志，若没有，则测试失败，流程结束。
8. 等待3秒，检查QCA测试目录下是否有daa-ac.crt文件，若没有，则测试失败，流程结束，否则，测试成功。

### 测试结果
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

## story2.3测试

### 测试思路
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

### 测试结果
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

## story2.4测试

### 测试思路
1. 在kunpengsecl根目录下进行 `make build` 编译。
2. 创建测试目录，并加载程序启动所需文件。
3. 启动AK Service。
4. 等待3秒，添加-C 2参数启动QCA Demo。
5. 等待3秒，检查QCA Demo是否把AK Service签发的AK证书存入TEE侧，若没有，则测试失败，流程结束。
6. 等待3秒，添加-T -U f68fd704-6eb1-4d14-b218-722850eb3ef0参数启动ATTESTER Demo。
7. 等待3秒，终止AK Service、QCA Demo和ATTESTER Demo进程。
8. 等待3秒，检查QCA Demo是否生成给定ID TA的完整性报告，若没有，则测试失败，流程结束，否则，测试成功。

### 测试结果
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

## story2.5测试

### 测试思路
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

### 测试结果
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

## story2.6测试

### 测试思路
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

### 测试结果
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
