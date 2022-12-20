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

#include <tee_defines.h>
#include <kta_command.h>

#define MAX_CERT_LEN 8192
#define MAX_KEY_LEN 2048
#define PARAM_COUNT 4

extern Cache cache;
extern CmdQueue cmdqueue;
extern ReplyCache replycache;

TEE_Result KTAInitialize(uint32_t param_type, TEE_Param params[PARAM_COUNT]){
    //basic function for calling the above functions
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[0].memref.size == 0 || params[0].memref.size > MAX_KEY_LEN || params[0].memref.buffer == NULL) {
        tloge("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[1].memref.size == 0 || params[1].memref.size > MAX_CERT_LEN || params[1].memref.buffer == NULL) {
        tloge("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[2].memref.size == 0 || params[2].memref.size > MAX_KEY_LEN || params[2].memref.buffer == NULL) {
        tloge("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[3].memref.size == 0 || params[3].memref.buffer == NULL) {
        tloge("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = saveKeyandCert("sec_storage_data/kcmpub.txt", params[0].memref.buffer, params[0].memref.size);
    if (ret != TEE_SUCCESS){
        tloge("save kcmpub failed\n");
        return ret;
    }
    ret = saveKeyandCert("sec_storage_data/ktacert.txt", params[1].memref.buffer, params[1].memref.size);
    if (ret != TEE_SUCCESS){
        tloge("save kta cert failed\n");
        return ret;
    }
    ret = saveKTAPriv("sec_storage_data/ktakey.txt", params[2].memref.buffer);
    if (ret != TEE_SUCCESS){
        tloge("save ktakey failed\n");
        return ret;
    }
    ret = initStructure();
    if (ret != TEE_SUCCESS){
        tloge("init kta struct failed\n");
        return ret;
    }

    ret = restoreKeyandCert("sec_storage_data/ktacert.txt", params[3].memref.buffer, &params[3].memref.size);
    if (ret != TEE_SUCCESS){
        tloge("restore kta cert failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}
