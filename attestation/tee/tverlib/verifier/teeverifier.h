#ifndef __VERIFIER_LIB__
#define __VERIFIER_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>

//Attester will send the report by this type
typedef struct{
    uint32_t size;
    uint8_t *buf;
} buffer_data;

enum error_status_code {
    TVS_ALL_SUCCESSED = 0,
    TVS_VERIFIED_NONCE_FAILED = -1,
    TVS_VERIFIED_SIGNATURE_FAILED = -2,
    TVS_VERIFIED_HASH_FAILED = -3,
};

int tee_verify_report(buffer_data *data_buf,buffer_data *nonce,int type, char *filename);
bool getDataFromAkCert(buffer_data *akcert, buffer_data *signdata, buffer_data *signdrk, buffer_data *certdrk, buffer_data *akpub);
bool verifysig(buffer_data *data, buffer_data *sign, buffer_data *cert, uint32_t scenario);

#endif