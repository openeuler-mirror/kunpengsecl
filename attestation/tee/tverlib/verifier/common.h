#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include "verifier.h"

#define USER_DATA_SIZE 64
#define NODE_LEN 8

#define UUID_SIZE 16
#define HASH_SIZE 32
// #define SIG_SIZE 512
// #define CERT_SIZE 512

#define MAXSIZE 1000
#define DATABUFMIN 100
#define DATABUFMAX 10000

#define PRIVATEKEY "./private_key.pem"
#define PUBLICKEY "./public_key.pem"

struct ra_data_offset {
    uint32_t data_len;
    uint32_t data_offset;
};

enum ra_tags {
    RA_TAG_SIGN_TYPE     = 0,
    RA_TAG_HASH_TYPE     = 1,
    RA_TAG_QTA_IMG_HASH  = 0,
    RA_TAG_TA_IMG_HASH   = 1,
    RA_TAG_QTA_MEM_HASH  = 2,
    RA_TAG_TA_MEM_HASH   = 3,
    RA_TAG_RESERVED      = 4,
    RA_TAG_AK_PUB        = 5,
    RA_TAG_SIGN_DRK      = 6,
    RA_TAG_SIGN_AK       = 7,
    RA_TAG_CERT_DRK      = 8,
    RA_TAG_CERT_AK       = 9,
};

struct __attribute__((__packed__)) ra_params {
    uint32_t tags; 
    union {
        uint32_t integer;
        struct ra_data_offset blob;
    } data;
};

typedef struct tee_uuid {
    uint32_t timeLow;
    uint16_t timeMid;
    uint16_t timeHiAndVersion;
    uint8_t clockSeqAndNode[NODE_LEN];
} TEE_UUID;

//the content of *buf(in buffer_data) be like...
typedef struct __attribute__((__packed__)) report_response {
    uint32_t version;
    uint64_t ts;
    uint8_t nonce[USER_DATA_SIZE];
    TEE_UUID uuid;
    uint32_t scenario;
    uint32_t param_count;
    struct ra_params params[0]; 
    /* following buffer data:
     * (1)ta_img_hash []
     * (2)ta_mem_hash []
     * (3)reserverd []
     * (4)sign_ak []
     * (5)ak_cert []
     */
} report_get;

typedef struct {
	uint32_t    version;
    uint64_t    timestamp;
	uint8_t		nonce[USER_DATA_SIZE];
	uint8_t 	uuid[UUID_SIZE];
    uint32_t    scenario;
	uint32_t	sig_alg;  //Signature algorithm type
	uint32_t	hash_alg; //Hash algorithm type
	uint8_t		image_hash[HASH_SIZE];
	uint8_t		hash[HASH_SIZE];
	uint8_t		reserve[HASH_SIZE];
	// uint8_t		signature[SIG_SIZE];
	// uint8_t 	cert[CERT_SIZE];  //AK cert
    uint8_t     *signature;
    uint8_t     *cert;
} TA_report;

#define KEY_PURPOSE_SIZE 32 //test
struct ak_cert {
uint32_t version;
uint64_t ts;
char purpose[KEY_PURPOSE_SIZE];
uint32_t param_count;
struct ra_params params[0];
/* following buffer data:
* (1)qta_img_hash []
 * (2)qta_mem_hash []
 * (3)reserverd []
 * (4)ak_pub []
* (5)sign_drk []
* (6)cert_drk []
*/
} __attribute__ ((__packed__));

typedef struct {
    uint8_t 	uuid[UUID_SIZE];
    uint8_t 	valueinfo[2][HASH_SIZE];     //valueinfo[0]=img measurement and valueinfo[1]=mem measurement
} base_value;

static void error(const char *msg);
static void file_error(const char *s);
static TA_report *Convert(buffer_data *buf_data);
// static void parse_uuid(uint8_t *uuid, TEE_UUID buf_uuid);
static void read_bytes(void *input, size_t size, size_t nmemb, uint8_t* output, size_t *offset);
static base_value *LoadBaseValue(const TA_report *report, char *filename);
static void str_to_uuid(const char *str, uint8_t *uuid);
static void uuid_to_str(const uint8_t *uuid, char *str);
static void str_to_hash(const char *str, uint8_t *hash);
static void hash_to_str(const uint8_t *hash, char *str);
static void hex2str(const uint8_t *source, int source_len, char *dest);
static void str2hex(const char *source, int source_len, uint8_t *dest);
static char *file_to_buffer(char *file, size_t *file_length);
static bool Compare(int type, TA_report *report, base_value *basevalue);
static bool cmp_bytes(const uint8_t *a, const uint8_t *b, size_t size);
static void test_print(uint8_t *printed,int printed_size,char *printed_name);
static void save_basevalue(const base_value *bv);