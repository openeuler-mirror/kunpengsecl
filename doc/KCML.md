# KCML

## KCML介绍

KCML是KTA向所有TA提供的一组接口，供TA使用KCMS提供的密钥缓存管理服务。

## KCML使用方式

开发人员可以在开发TA源代码时，通过引入头文件**kcml.h**的方式使用接口，接口采用TA调用TA的方式。

## KCML接口介绍

### generate_key

`TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *masterkey);`

接口描述：生成新密钥请求接口。TA调用此接口生成一个创建新密钥的请求。

参数1：[INPUT]TA的UUID值

参数2：[INPUT]TA在KMS中的账号

参数3：[INPUT]TA在KMS中账号对应的密码

参数4：[INPUT]TA在KMS中的用户主密钥ID

返回值：TEE_SUCCESS为操作成功，其它为失败。

### search_key

`TEE_Result search_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey, uint8_t *keyvalue, uint32_t *flag);`

接口描述：查找密钥接口。TA调用此接口查询一个已使用过的密钥

参数1：[INPUT]TA的UUID值

参数2：[INPUT]TA在KMS中的账号

参数3：[INPUT]TA在KMS中账号对应的密码

参数4：[INPUT]TA需要查询的密钥ID

参数5：[INPUT]TA在KMS中的用户主密钥ID

参数6：[OUTPUT]查询的密钥ID对应的密钥明文

参数7：[OUTPUT]标志是否需要再次查询，为0表示KTA中查询到缓存的密钥值，为1表示KTA中未查询到缓存的密钥值，需要TA在一段时间后再次查询

返回值：TEE_SUCCESS为操作成功，其它为失败。

### delete_key

`TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid);`

接口描述：清除指定密钥缓存接口。TA调用此接口生成清除一个密钥在KCM和KTA中缓存的请求

参数1：[INPUT]TA的UUID值

参数2：[INPUT]TA在KMS中的账号

参数3：[INPUT]TA在KMS中账号对应的密码

参数4：[INPUT]需要清除缓存的密钥ID

返回值：TEE_SUCCESS为操作成功，其它为失败。

### clear_cache

`TEE_Result clear_cache(TEE_UUID *uuid, uint8_t *account, uint8_t *password);`

接口描述：清除所有密钥缓存接口。TA调用此接口清除其全部在KTA中的缓存

参数1：[INPUT]TA的UUID值

参数2：[INPUT]TA在KMS中的账号

参数3：[INPUT]TA在KMS中账号对应的密码

返回值：TEE_SUCCESS为操作成功，其它为失败。

### get_kcm_reply

`TEE_Result get_kcm_reply(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid, uint8_t *keyvalue);`

接口描述：获取KCM返回信息接口。TA在调用**generate_key**接口或**delete_key**接口后一段时间后调用此接口获取返回。

参数1：[INPUT]TA的UUID值

参数2：[INPUT]TA在KMS中的账号

参数3：[INPUT]TA在KMS中账号对应的密码

参数4：[OUTPUT]若在调用**generate_key**接口后调用此接口，该参数为生成的新密钥ID；若在调用**delete_key**接口后调用此接口，该参数为空

参数5：[OUTPUT]若在调用**generate_key**接口后调用此接口，该参数为生成的新密钥明文；若在调用**delete_key**接口后调用此接口，该参数为空

返回值：TEE_SUCCESS为操作成功，其它为失败。

## KCML使用示例

我们提供了**demo_ca_for_kcms.c**和**demo_ta_for_kcms.c**两个demo示例演示如何调用KCML来使用KCMS提供的服务
