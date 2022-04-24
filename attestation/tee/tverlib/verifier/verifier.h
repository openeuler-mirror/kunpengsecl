#ifndef __VERIFIER_LIB__
#define __VERIFIER_LIB__

#include <stdio.h>
#include <stdbool.h>

typedef struct
{
    __uint32_t size;
    __uint8_t *buf;
} TAreport;

typedef struct
{
    char* Mmem;
    char* Minit;
    char* Mimg;
} BaseValue;

bool VerifySignature(TAreport *report);

bool Validate(TAreport *manifest, BaseValue *basevalue);

#endif