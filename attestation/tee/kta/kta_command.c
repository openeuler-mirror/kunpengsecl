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
#include <tee_object_api.h>
#include <tee_mem_mgmt_api.h>
#include <securec.h>
#include <kta_command.h>
#include <cJSON.h>

#define MAX_CERT_LEN 8192
#define MAX_KEY_LEN 2048
#define MAX_FINAL_SIZE 2048
#define PARAM_COUNT 4

extern Cache cache;
extern HashCache hashcache;
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

    ret = restoreKeyandCert("sec_storage_data/ktacert.txt", params[3].memref.buffer, params[3].memref.size);
    if (ret != TEE_SUCCESS){
        tloge("restore kta cert failed,ret=0x%x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}


TEE_Result GetTaHash(uint32_t param_type, TEE_Param params[PARAM_COUNT]){
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size == 0) {
        tloge("Bad expected parameter value\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FOURTH].value.a > 32) {
        tloge("The number of ta hash values is out of memory\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FOURTH].value.a <= 0) {
        tloge("Not enough ta hash values, unable to conduct local attestation\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *hashjson = TEE_Malloc((params[PARAMETER_FRIST].memref.size + 1)*sizeof(uint8_t), 0);
    errno_t err = memcpy_s(hashjson, params[PARAMETER_FRIST].memref.size,
            params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    if (err != EOK) {
        tloge("Get ta hash values failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    tlogd("buffer size: %d", params[PARAMETER_FRIST].memref.size);
    ret = saveHashValues(hashjson, params[PARAMETER_FOURTH].value.a);
    if (ret != TEE_SUCCESS) {
        tloge("Save ta hash values failed!\n");
        return TEE_ERROR_WRITE_DATA;
    }
    TEE_Free(hashjson);
    tlogd("get and save ta hash values success");
    return TEE_SUCCESS;
}

TEE_Result SendRequest(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    CmdNode curNode;
    char *finalrequest = TEE_Malloc(sizeof(char)*MAX_FINAL_SIZE, 0);
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL ||
        params[PARAMETER_FRIST].memref.size == 0) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    //Judge whether cmd queue is empty 
    if (cmdqueue.head == cmdqueue.tail){
        params[PARAMETER_SECOND].value.a = 0;
        params[PARAMETER_SECOND].value.b = 0;
        tlogd("cmdqueue is empty,nothing should be sent.\n");
        return TEE_SUCCESS;
    }
    //if is not empty, dequeue a request from the queue
    params[PARAMETER_SECOND].value.a = (cmdqueue.tail + MAX_QUEUE_SIZE - cmdqueue.head) % MAX_QUEUE_SIZE;
    curNode = dequeue();
    //generate Request Return value for ka
    ret = generateFinalRequest(curNode, finalrequest);
    if (ret != TEE_SUCCESS) {
        tloge("fail to generate final request");
        return TEE_ERROR_OVERFLOW;
    }
    params[PARAMETER_SECOND].value.b = strlen(finalrequest);
    errno_t err = memcpy_s(params[PARAMETER_FRIST].memref.buffer,
            params[PARAMETER_FRIST].memref.size, finalrequest, strlen(finalrequest));
    if(err != 0) {
        tloge("buffer is too short");
        return TEE_ERROR_SHORT_BUFFER;
    }
    params[PARAMETER_FRIST].memref.size = params[PARAMETER_SECOND].value.b;
    tlogd("send request success");
    TEE_Free(finalrequest);
    return TEE_SUCCESS;
}

TEE_Result GetResponse(uint32_t param_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    if (!check_param_type(param_type,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types, 0x%x.\n", param_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAMETER_FRIST].memref.buffer == NULL || params[PARAMETER_FRIST].memref.size == 0) {
        tloge("Bad expected parameter value");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = handleResponse(params[PARAMETER_FRIST].memref.buffer, params[PARAMETER_FRIST].memref.size);
    if (ret != TEE_SUCCESS) {
        tloge("Handle response from ka failed");
        params[PARAMETER_SECOND].value.a = 0;
        return ret;
    }
    params[PARAMETER_SECOND].value.a = 1;
    return TEE_SUCCESS;
}

//Interface reserved for resetting KTA
TEE_Result ResetAll(){
    TEE_Result ret;
    ret = reset("sec_storage_data/ktacert2.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset ktacert\n", ret);
        return ret;
    }
    ret = reset("sec_storage_data/kcmpub2.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset kcmpub\n", ret);
        return ret;
    }
    ret = reset("sec_storage_data/ktakey2.txt");
    if (ret != TEE_SUCCESS) {
        tloge("Failed to reset ktakey\n", ret);
        return ret;
    }
    ret = initStructure();
    if (ret != TEE_SUCCESS) {
        tloge("Failed to initialize storage structure\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}