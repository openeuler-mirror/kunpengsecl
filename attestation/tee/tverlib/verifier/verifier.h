#ifndef __VERIFIER_LIB__
#define __VERIFIER_LIB__

#include <stdio.h>
#include <stdbool.h>

typedef struct
{
    __uint32_t size;
    __uint8_t *buf;
} buffer_data;

typedef struct
{
    char* Mmem;
    char* Minit;
    char* Mimg;
} BaseValue;

bool VerifySignature(buffer_data *report);

bool VerifyManifest(buffer_data *data,int type,char *filename);

#endif