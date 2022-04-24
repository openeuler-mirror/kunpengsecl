// a simulation of qcalib

#ifndef __QCA_LIB__
#define __QCA_LIB__

#include <stdio.h>
#include <stdbool.h>

typedef struct
{
    /* data */
    __uint32_t size;
    __uint8_t *buf;
} ra_buffer_data;

typedef ra_buffer_data TEEC_Result;
typedef __int64_t TEEC_UUID;

TEEC_Result RemoteAttestReport(TEEC_UUID ta_uuid, ra_buffer_data *usr_data, ra_buffer_data *report, bool with_tcb);

#endif