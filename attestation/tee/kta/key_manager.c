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
#include <key_manager.h>

TEE_Result SearchKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache, char *keyvalue) {
    //todo: options to search a certain key in cache

    //input: TA_uuid, keyid, cache
    //output: cache, keyvalue
}

TEE_Result SaveKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue, Cache *cache) {
    //todo: options to save a certain key in cache

    //input: TA_uuid, keyid, keyvalue, cache
    //output: cache
}

TEE_Result DeleteKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache) {
    //todo: options to delete a certain key in cache

    //input: TA_uuid, keyid
    //output: cache
}

TEE_Result DestoryCache(Cache *cache) {
    //todo: options to destory cache

    //input: cache
}