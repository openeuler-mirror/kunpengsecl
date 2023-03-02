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
	2. 2022-11-18   waterh2o
        redefine some interface
*/

#ifndef KTA_API_H
#define KTA_API_H

#include <tee_defines.h>
#include <kta_common.h>

#define PARAM_COUNT 4

//for kcm

TEE_Result KTAInitialize(uint32_t param_types, TEE_Param params[PARAM_COUNT]);
TEE_Result SendRequest(uint32_t param_type, TEE_Param params[PARAM_COUNT]);
TEE_Result GetResponse(uint32_t param_type, TEE_Param params[PARAM_COUNT]);


//for TA

TEE_Result GenerateTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]);
TEE_Result SearchTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]);
TEE_Result DeleteTAKey(uint32_t param_type, TEE_Param params[PARAM_COUNT]); 
TEE_Result GetKcmReply(uint32_t param_type, TEE_Param params[PARAM_COUNT]);
TEE_Result ClearCache(uint32_t param_type, TEE_Param params[PARAM_COUNT]) ;
#endif