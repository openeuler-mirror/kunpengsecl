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


bool tee_verify_signature(buffer_data *report);
bool tee_verify(buffer_data *buf_data, int type, char *filename);


#endif