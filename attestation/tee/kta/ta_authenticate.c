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

#include <tee_defines.h>
#include <tee_ra_api.h>
#include <tee_crypto_api.h>
#include <securec.h>
#include <string.h>
#include <kta_common.h>
#include <cJSON.h>
#include <b64/b64.h>

#define NONCE_SIZE 32
#define CHECK_SUCCESS 1
#define CHECK_FAIL 0
extern Cache cache;
extern CmdQueue cmdqueue;
extern ReplyCache replycache;

//check the id1 and the id2 equal
bool checkUuid(TEE_UUID id1,TEE_UUID id2)
{
    if(id1.timeHiAndVersion != id2.timeHiAndVersion || 
    id1.timeLow != id2.timeLow ||
    id1.timeMid != id2.timeMid){
        return false;
    }
    for(int32_t i = 0;i < NODE_LEN; i++){
        if(id1.clockSeqAndNode[i] != id2.clockSeqAndNode[i]){
            return false;
        }
    }
    return true;
}

// return -1 when ta is not exist, return 0 when success, return 1 when account is not match
int32_t verifyTAPasswd(TEE_UUID TA_uuid, uint8_t *account, uint8_t *password) {
    //step1: check the queue is or not is empty
    if (cache.head == END_NULL && cache.tail == END_NULL)
    {
         tlogd("Failed to get a valid cache!\n");
         return -1;
    }
    //step2: find the TA_uuid from the cache
    int32_t front = cache.head;//don not change the original value
    while (front != END_NULL && !checkUuid(TA_uuid,cache.ta[front].id))
    {
        //loop
        front = cache.ta[front].next; //move to next one
    }
    if (front == END_NULL) {
        tloge("Failed to verify the TA password!\n");
        return -1;
    }
    //step3: compare the cache's value with account and password
    if(!memcmp(account,cache.ta[front].account,sizeof(cache.ta[front].account)) 
    && !memcmp(password,cache.ta[front].password,sizeof(cache.ta[front].password)))
    {
        tlogd("success to verify the TA password");
        return 0;
    }
    tloge("Failed to verify the TA password");
    return 1;
}

//Encode unsigned char source to base64url.
//Neither of param source_len or dest_len include character '\0'.
//Return the first address of encoded string.
char* base64urlencode(const uint8_t *source, size_t source_len, size_t *dest_len) {
    char *dest = b64_encode(source, source_len);
    *dest_len = strlen(dest);
    //change "+" to "-", "/" to "_", remove "=".
    for(int i = *(int *)dest_len; i >= 0; i--) {
        if(*(dest + i) == '+')
            *(dest + i) = '-';
        else if(*(dest + i) == '/')
            *(dest + i) = '_';
        else if(*(dest + i) == '=') 
            *(dest + i) = *(dest + i + 1);
    }
    return dest;
}

//Decode base64url string source to unsigned char.
//Neither of param source_len or dest_len include character '\0'.
//Return the first address of decoded unsigned string.
uint8_t* base64urldecode(const char *source, size_t source_len, size_t *dest_len) {
    //change "-" to "+", "_" to "/", add back "=".
    size_t i = 0;
    char *tail1 = "=";
    char *tail2 = "==";
    char *b64 = TEE_Malloc(source_len + 3, 0);
    memcpy_s(b64, source_len + 3, source, source_len);
    for(i = 0; i < source_len; i++) {
        if(*(b64 + i) == '-')
            *(b64 + i) = '+';
        else if(*(b64 + i) == '_')
            *(b64 + i) = '/';
    }
    *(b64 + i) = '\0';
    if(source_len % 4 == 2) {
        strcat_s(b64, source_len + 3, tail2);
        *dest_len = (source_len + 2) / 4 * 3 - 2;
    }
    else if(source_len % 4 == 3) {
        strcat_s(b64, source_len + 3, tail1);
        *dest_len = (source_len + 1) / 4 * 3 - 1;
    }
    else if(source_len % 4 == 0)
        *dest_len = source_len / 4 * 3;
    uint8_t *dest = b64_decode(b64, strlen(b64));
    TEE_Free(b64);
    return dest;
}

//generate in buffer in local attestation scenario
TEE_Result generateinbuffer(uint8_t *taid, char *noncebuf, struct ra_buffer_data *in) {
    cJSON *injson = NULL;
    cJSON *inpayload = NULL;
    cJSON *version = NULL;
    cJSON *b64_nonce = NULL;
    cJSON *uuid = NULL;
    cJSON *hash_alg = NULL;
    cJSON *with_tcb = NULL;
    char *indata = NULL;
    //cJSON *daa_bsn = NULL;
    injson = cJSON_CreateObject();
    cJSON_AddStringToObject(injson, "handler", "report-input");
    inpayload = cJSON_CreateObject();
    version = cJSON_CreateString("TEE.RA.1.0");
    if(version == NULL) {
        tloge("kta local attest: version is null\n");
        goto end;
    }
    cJSON_AddItemToObject(inpayload, "version", version);
    uuid = cJSON_CreateString((char*)taid);
    if(uuid == NULL) {
        tloge("kta local attest: uuid is null\n");
        goto end;
    }
    b64_nonce = cJSON_CreateString(noncebuf);
    if(b64_nonce == NULL) {
        tloge("kta local attest: nonce is null\n");
        goto end;
    }
    free(noncebuf);
    cJSON_AddItemToObject(inpayload, "nonce", b64_nonce);
    cJSON_AddItemToObject(inpayload, "uuid", uuid);
    hash_alg = cJSON_CreateString("HS256");
    if(hash_alg == NULL) {
        tloge("kta local attest: hash_alg is null\n");
        goto end;
    }
    cJSON_AddItemToObject(inpayload, "hash_alg", hash_alg);
    with_tcb = cJSON_CreateFalse();
    if(with_tcb == NULL) {
        tloge("kta local attest: with_tcb is null\n");
        goto end;
    }
    cJSON_AddItemToObject(inpayload, "with_tcb", with_tcb);
    /*
    daa_bsn = cJSON_CreateString("");
    if(daa_bsn == NULL) {
        tloge("kta local attest: daa_bsn is null\n");
        goto end;
    }
    cJSON_AddItemToObject(inpayload, "daa_bsn", daa_bsn);
    */
    cJSON_AddItemToObject(injson, "payload", inpayload);
    indata = cJSON_Print(injson);
    in->buffer = TEE_Malloc(strlen(indata) + 1, 0);
    memcpy_s(in->buffer, strlen(indata) + 1, indata, strlen(indata) + 1);
    in->length = strlen(indata) + 1;
    cJSON_free(indata);
    return TEE_SUCCESS;
end:
    cJSON_Delete(injson);
    return TEE_ERROR_GENERIC;
}

//compare hash value to conduct local attestation
bool comparehash(HashValue *hash, char *ta_img, char *ta_mem) {
    bool status = CHECK_FAIL;
    if(strcmp(hash->img_hash, ta_img)) {
        goto end;
    }
    if(strcmp(hash->mem_hash, ta_mem)) {
        goto end;
    }
    status = CHECK_SUCCESS;
end:
    return status;
}

//verify drk signature using ak_pub, drk_sign, drk_cert, and payload in akcert
/*
bool verifydrksign(char *drk_data, char *ak_pub, char *drk_sign, char *drk_cert) {
    //bool status = CHECK_FAIL;
    (void)drk_data;
    (void)ak_pub;
    (void)drk_sign;
    (void)drk_cert;
    return CHECK_SUCCESS;
}
*/

//check whether fields of out buffer are valid
bool handleoutbuffer(uint8_t *taid, char *noncebuf, HashValue *hash, struct ra_buffer_data *out) {
    bool status = CHECK_FAIL;
    cJSON *handler = NULL, *payload = NULL, *report_sign = NULL,
            *akcert = NULL, *b64_nonce = NULL, *scenario = NULL,
            *uuid = NULL, *ta_img = NULL, *ta_mem = NULL,
    //        *akcert_noas = NULL, *drk_data = NULL, *ak_pub = NULL,
    //        *signature = NULL, *drk_sign = NULL, *drk_cert = NULL;
    cJSON *outdata = cJSON_Parse((char*)out->buffer);
    if(outdata == NULL) {
        tloge("parse json data failed!\n");
        goto end1;
    }
    handler = cJSON_GetObjectItemCaseSensitive(outdata, "handler");
    if(handler == NULL || strcmp(handler->valuestring, "report-output") != 0) {
        tloge("check handler failed!\n");
        goto end1;
    }
    payload = cJSON_GetObjectItemCaseSensitive(outdata, "payload");
    if(payload == NULL) {
        tloge("check payload failed!\n");
        goto end1;
    }
    report_sign = cJSON_GetObjectItemCaseSensitive(outdata, "report_sign");
    if(report_sign == NULL) {
        tloge("check report_sign failed!\n");
        goto end1;
    }
    akcert = cJSON_GetObjectItemCaseSensitive(outdata, "akcert");
    if(akcert == NULL) {
        tloge("check akcert failed!\n");
        goto end1;
    }
    b64_nonce = cJSON_GetObjectItemCaseSensitive(payload, "nonce");
    if(b64_nonce == NULL || strcmp(b64_nonce->valuestring, noncebuf)) {
        tloge("check nonce value failed!\n");
        goto end1;
    }
    scenario = cJSON_GetObjectItemCaseSensitive(payload, "scenario");
    if(scenario == NULL || strcmp(scenario->valuestring, "sce_no_as")) {
        tloge("check scenario failed!\n");
        goto end1;
    }
    uuid = cJSON_GetObjectItemCaseSensitive(payload, "uuid");
    if(uuid == NULL || strcmp(uuid->valuestring, (char*)taid)) {
        tloge("check uuid failed!\n");
        goto end1;
    }
    ta_img = cJSON_GetObjectItemCaseSensitive(payload, "ta_img");
    if(ta_img == NULL) {
        tloge("check ta_img failed!\n");
        goto end1;
    }
    ta_mem = cJSON_GetObjectItemCaseSensitive(payload, "ta_mem");
    if(ta_mem == NULL) {
        tloge("check ta_mem failed!\n");
        goto end1;
    }
    if(!comparehash(hash, ta_img->valuestring, ta_mem->valuestring)) {
        tloge("compare ta hash values failed!\n");
        goto end1;
    }
/*
    akcert_noas = cJSON_GetObjectItemCaseSensitive(akcert, "sce_no_as");
    if(akcert_noas == NULL) {
        tloge("check akcert failed!\n");
        goto end1;
    }
    drk_data = cJSON_GetObjectItemCaseSensitive(akcert_noas, "payload");
    if(drk_data == NULL) {
        tloge("check akcert_payload failed!\n");
        goto end1;
    }
    ak_pub = cJSON_GetObjectItemCaseSensitive(drk_data, "ak_pub");
    if(ak_pub == NULL) {
        tloge("check ak_pub failed!\n");
        goto end1;
    }
    signature = cJSON_GetObjectItemCaseSensitive(akcert_noas, "signature");
    if(signature == NULL) {
        tloge("check signature failed!\n");
        goto end1;
    }
    drk_sign = cJSON_GetObjectItemCaseSensitive(signature, "drk_sign");
    if(drk_sign == NULL) {
        tloge("check drk_sign failed!\n");
        goto end1;
    }
    drk_cert = cJSON_GetObjectItemCaseSensitive(signature, "drk_cert");
    if(drk_cert == NULL) {
        tloge("check drk_cert failed!\n");
        goto end1;
    }
    char *drk_datastring = cJSON_Print(drk_data);
    if(!verifydrksign(drk_datastring, ak_pub->valuestring,
            drk_sign->valuestring, drk_cert->valuestring)) {
        tloge("verify drk signature failed!\n");
        goto end2;
    }
*/
    status = CHECK_SUCCESS;
/*
end2:
    cJSON_free(drk_datastring);
*/
end1:
    cJSON_Delete(outdata);
    return status;
}

//conduct local attestation
TEE_Result localAttest(uint8_t *taid, HashValue *hash) {
    TEE_Result ret = TEE_SUCCESS;
    struct ra_buffer_data in;
    struct ra_buffer_data out;
    uint8_t nonce[NONCE_SIZE] = {0};
    size_t noncelen = NONCE_SIZE;
    char *noncebuf = NULL;
    size_t noncebuflen = 0;
    TEE_GenerateRandom(nonce, noncelen);
    noncebuf = base64urlencode(nonce, noncelen, &noncebuflen);
    tlogd("%s",noncebuf);
    out.buffer = TEE_Malloc(12288, 0);
    out.length = 12288;
    ret = generateinbuffer(taid, noncebuf, &in);
    if(ret != TEE_SUCCESS) {
        tloge("kta local attest: generate in buffer failed!\n");
        goto end;
    }
    tlogd("%s", in.buffer);
    ret = ra_local_report(&in, &out);
    if(ret != TEE_SUCCESS) {
        tloge("get local attest report failed!\n");
        goto end;
    }
    if(handleoutbuffer(taid, noncebuf, hash, &out))
        tlogi("local attestation process succeeded.\n");
    else 
        ret = TEE_ERROR_ACCESS_DENIED;
end:
    TEE_Free(out.buffer);
    TEE_Free(in.buffer);
    return ret;
}
