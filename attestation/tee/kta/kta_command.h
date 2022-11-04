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

#ifndef KTA_API_H
#define KTA_API_H

#include <tee_defines.h>
#include <kta_initialize.h>
#include <key_manager.h>

TEE_Result SendRequest(); //parameters to be set

TEE_Result HandleKAReply(); //parameters to be set

TEE_Result SearchTAKey(TEE_UUID TA_uuid, char *keyid, Cache *cache, char *keyvalue);

TEE_Result DeleteTAKey(TEE_UUID TA_uuid, char *keyid, Cache *cache);

TEE_Result DestoryTAKey(TEE_UUID TA_uuid, char *keyid, Cache *cache); //parameters to be set

TEE_Result SendReplytoTA(); //如果异步实现，ta需要再次调用kta获取返回结果

#endif