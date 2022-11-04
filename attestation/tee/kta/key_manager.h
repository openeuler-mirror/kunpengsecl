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

#ifndef KEY_MANAGER_H
#define KEY_MANAGER_H

#include <kta_initialize.h>

TEE_Result SearchKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache, char *keyvalue);

TEE_Result SaveKey(TEE_UUID TA_uuid, uint32_t keyid, char *keyvalue, Cache *cache);

TEE_Result DeleteKey(TEE_UUID TA_uuid, uint32_t keyid, Cache *cache);

TEE_Result DestoryCache(Cache *cache);

#endif 