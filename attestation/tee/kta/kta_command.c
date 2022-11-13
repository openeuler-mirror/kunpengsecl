/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: leezhenxiang
Create: 2022-11-04
Description: api module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
*/

#include <tee_defines.h>
#include <kta_command.h>

TEE_Result SendRequest() {
    //todo: send request to ka when ka polls, and answer ta trusted state which ka asks
}

TEE_Result HandleReply() {
    //todo: handle ta's reply
}

TEE_Result EncodeRequest(void *kmskey, CmdQueue cmdqueue) {
    //todo: encode cmd with kmskey

    //input: kmskey, cmdqueue
    //output: cmdqueue
}

TEE_Result DncodeRequest(void *kmskey, CmdQueue cmdqueue) {
    //todo: decode cmd with kmskey
    
    //input: kmskey, cmdqueue
    //output: cmdqueue
}

TEE_Result SaveTAKey(TEE_UUID TA_uuid, char *keyid, char *keyvalue, Cache *cache) {
    //todo: save a key value into the cache

    //input: TA_uuid, keyid, keyvalue, cache
    //output: cache
}

//the following operation must start with ta authenticating

TEE_Result SearchTAKey(TEE_UUID TA_uuid, char *keyid, Cache *cache, char *keyvalue) {
    //todo: search a certain ta key, if not exist, call AddTATable() to add a request

    //input: TA_uuid, keyid, cache
    //output: cache, keyvalue
}

TEE_Result DeleteTAKey(TEE_UUID TA_uuid, char *keyid, Cache *cache) {
    //todo: delete a certain key in the cache

    //input: TA_uuid, keyid, cache
    //output: cache
}

TEE_Result DestoryKey(TEE_UUID TA_uuid, char *keyid, Cache *cache) {
    //todo: delete a certain key by calling DeleteTAKey(), then generate a delete key request in TaCache

    //input: TA_uuid, keyid, cache
    //output: cache
}

TEE_Result SendReplytoTA() {
    //todo: answer to ta when ta asks its command's reply.
}