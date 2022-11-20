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
Description: key managing module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
*/

#include <tee_defines.h>
#include <kta_common.h>

TEE_Result SendRequest() {
    //todo: send request to ka when ka polls, and answer ta trusted state which ka asks
}

TEE_Result GetResponse() {
    //todo: Get Response from ka when kta had sent request to kcm before
}

// Communication with ta

TEE_Result SendReplytoTA() {
    //todo: answer to ta when ta asks its command's reply.
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


void saveKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue, Cache *cache) {
    //todo: options to save a certain key in cache

    //input: TA_uuid, keyid, keyvalue, cache
    //output: cache
}

void encodeRequest(void *kmskey, CmdQueue cmdqueue) {
    //todo: encode cmd with kmskey

    //input: kmskey, cmdqueue
    //output: cmdqueue
}

void decodeRequest(void *kmskey, CmdQueue cmdqueue) {
    //todo: decode cmd with kmskey
    
    //input: kmskey, cmdqueue
    //output: cmdqueue
}
