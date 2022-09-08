// a simulation of qcalib

#ifndef __QCA_LIB__
#define __QCA_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define KEY_TAG_TYPE_MOVE_BITS 28
#define RA_INTEGER (1 << KEY_TAG_TYPE_MOVE_BITS)
#define RA_BYTES   (2 << KEY_TAG_TYPE_MOVE_BITS)

/* scenario number */
#define RA_SCENARIO_NO_AS        0
#define RA_SCENARIO_AS_NO_DAA    1
#define RA_SCENARIO_AS_WITH_DAA  2

enum ra_alg_types {
    RA_ALG_RSA_3072     = 0x20000,
    RA_ALG_RSA_4096     = 0x20001,  // PSS padding
    RA_ALG_SHA_256      = 0x20002,
    RA_ALG_SHA_384      = 0x20003,
    RA_ALG_SHA_512      = 0x20004,
    RA_ALG_ECDSA        = 0x20005,
    RA_ALG_ED25519      = 0x20006,
    RA_ALG_SM2_DSA_SM3  = 0x20007,
    RA_ALG_SM3          = 0x20008,
    RA_ALG_DAA_GRP_FP256BN = 0x20009,
};

enum ra_tags {
    RA_TAG_SIGN_TYPE     = RA_INTEGER | 0,
    RA_TAG_HASH_TYPE     = RA_INTEGER | 1,
    RA_TAG_CURVE_TYPE    = RA_INTEGER | 2,
    RA_TAG_QTA_IMG_HASH  = RA_BYTES   | 0,
    RA_TAG_TA_IMG_HASH   = RA_BYTES   | 1,
    RA_TAG_QTA_MEM_HASH  = RA_BYTES   | 2,
    RA_TAG_TA_MEM_HASH   = RA_BYTES   | 3,
    RA_TAG_RESERVED      = RA_BYTES   | 4,
    RA_TAG_AK_PUB        = RA_BYTES   | 5,
    RA_TAG_SIGN_DRK      = RA_BYTES   | 6,
    RA_TAG_SIGN_AK       = RA_BYTES   | 7,
    RA_TAG_CERT_DRK      = RA_BYTES   | 8,
    RA_TAG_CERT_AK       = RA_BYTES   | 9,
};

struct ra_buffer_data {
    uint32_t size;
    uint8_t *buf;
};

struct ra_data_offset {
    uint32_t data_len;
    uint32_t data_offset;
};

struct ra_params {
    uint32_t tags;
    union {
        uint32_t integer;
        struct ra_data_offset blob;
    } data;
} __attribute__((__packed__));

struct ra_params_set_t {
    uint32_t param_count;
    struct ra_params params[0];
} __attribute__((__packed__));

typedef int TEEC_Result;
typedef struct
{
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[8];
} TEEC_UUID;

TEEC_Result RemoteAttestProvision(uint32_t scenario, struct ra_buffer_data *param_set, struct ra_buffer_data *out_data);

TEEC_Result RemoteAttestReport(TEEC_UUID ta_uuid, struct ra_buffer_data *usr_data, struct ra_buffer_data *param_set, struct ra_buffer_data *report, bool with_tcb);

TEEC_Result RemoteAttestSaveAKCert(struct ra_buffer_data *akcert);

#endif