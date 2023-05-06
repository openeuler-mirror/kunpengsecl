/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

#ifndef __KCML_H__
#define __KCML_H__

#include <tee_defines.h>

#define MAX_STR_LEN 64
#define KEY_SIZE 4096
#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3

enum {
    CMD_KEY_GENETARE        = 0x70000001,
    CMD_KEY_SEARCH          = 0x70000002,
    CMD_KEY_DELETE          = 0x70000003,
    CMD_KCM_REPLY           = 0x70000004,
    CMD_CLEAR_CACHE         = 0x70000005
};

typedef struct _tagCmdNode{
    int32_t     cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    TEE_UUID    masterkey;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
} CmdNode;

typedef struct _tagReplyNode{
    int32_t tag;    //a tag to identify reply: 1 for generate reply, 2 for delete reply
    TEE_UUID    taId;
    TEE_UUID    keyId;
    union {
        uint8_t keyvalue[KEY_SIZE];
        int32_t flag;   //a flag to identify if the key is deleted successfully: 1 for deleted, 0 for not
    };
    int32_t next;   // -1: empty; 0~MAX_TA_NUM: next reply for search operation.
} ReplyNode;

/*
 * Generate a key using KCMS
 *
 * @param uuid [IN] the uuid of ta which needs the key
 * @param account [IN] ta's account in KMS
 * @param password [IN] ta's password in KMS
 * @param masterkey [IN] the uuid of ta's master key in KMS
 */
TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *masterkey);

/*
 * Search the key corresponding to the keyid using KCMS
 *
 * @param uuid [IN] the uuid of ta which needs the key
 * @param account [IN] ta's account in KMS
 * @param password [IN] ta's password in KMS
 * @param keyid [OUT] the id of the key to be searched for
 * @param masterkey [IN] the uuid of ta's master key in KMS
 * @param keyvalue [OUT] the value of the key
 * @param flag [OUT] a flag, whether need to search again
 */
TEE_Result search_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey, uint8_t *keyvalue, uint32_t *flag);

/*
 * Delete the key corresponding to the keyid in KMS using KCMS
 *
 * @param uuid [IN] the uuid of ta which needs the key
 * @param account [IN] ta's account in KMS
 * @param password [IN] ta's password in KMS
 * @param keyid [IN] the id of the key to be searched for
 */
TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid);

/*
 * Clear all of current ta's data in KTA
 *
 * @param uuid [IN] the uuid of ta which needs the key
 * @param account [IN] ta's account in KMS
 * @param password [IN] ta's password in KMS
 */
TEE_Result clear_cache(TEE_UUID *uuid, uint8_t *account, uint8_t *password);

/*
 * Get the reply of generating a key using KCMS
 *
 * @param uuid [IN] the uuid of ta which needs the key
 * @param account [IN] ta's account in KMS
 * @param password [IN] ta's password in KMS
 * @param keyid [IN] the id of the key to be searched for
 * @param keyvalue [OUT] the value of the key generated
 */
TEE_Result get_kcm_reply(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, uint8_t *keyvalue);
#endif // __KCML_H__
