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
Description: ta authenticating module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
*/

#ifndef TA_AUTHENTICATE
#define TA_AUTHENTICATE

#include <kta_initialize.h>

TEE_Result AddTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache);

TEE_Result DeleteTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache);

TEE_Result UpdateTaState(TEE_UUID TA_uuid, char *taId, char *passWd, Cache *cache);

void AttestTA(); //parameters to be set, return value to be set

#endif