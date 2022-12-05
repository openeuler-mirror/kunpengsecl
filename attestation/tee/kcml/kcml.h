#ifndef __KCML_H__
#define __KCML_H__

#include <tee_defines.h>
#include <kta_command.h>

#define MAX_STR_LEN 64
#define KEY_SIZE 128

#define PARAMETER_FRIST 0
#define PARAMETER_SECOND 1
#define PARAMETER_THIRD 2
#define PARAMETER_FOURTH 3

enum {
    CMD_KEY_GENETARE        = 0x80000001,
    CMD_KEY_SEARCH          = 0x80000002,
    CMD_KEY_DELETE          = 0x80000003,
    CMD_KEY_DESTORY         = 0x80000004,
    CMD_KCM_REPLY           = 0x80000005,
    CMD_CLEAR_CACHE         = 0x80000006
};

typedef struct _tagCmdData{
    int32_t     cmd;
    TEE_UUID    taId;
    TEE_UUID    keyId;
    TEE_UUID    masterkey;
    uint8_t account[MAX_STR_LEN];
    uint8_t password[MAX_STR_LEN];
}CmdData;

TEE_Result generate_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *masterkey, uint8_t *keyvalue);
TEE_Result search_key(TEE_UUID *uuid, uint8_t *account,
        uint8_t *password, TEE_UUID *keyid, TEE_UUID *masterkey, uint8_t *keyvalue);
TEE_Result delete_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid);
TEE_Result destory_key(TEE_UUID *uuid, uint8_t *account, uint8_t *password, TEE_UUID *keyid);
TEE_Result clear_cache(TEE_UUID *uuid, uint8_t *account, uint8_t *password);
//TEE_Result get_key_reply(uint8_t *keyvalue);

#endif // __KCML_H__
