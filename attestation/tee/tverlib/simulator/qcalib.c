// a simulation of qcalib

#include "qcalib.h"

TEEC_Result RemoteAttestReport(TEEC_UUID ta_uuid, ra_buffer_data *usr_data, ra_buffer_data *report, bool with_tcb) {
    ra_buffer_data testdata;
    __uint8_t *test_buf = "All the report infomation, which just for test!";
    testdata.buf = test_buf;
    return testdata;
}
