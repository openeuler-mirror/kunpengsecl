/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: leezhenxiang
Create: 2022-11-04
Description: ta authenticating module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
*/

#include <tee_defines.h>
#include <kta_common.h>
#include <string.h>
bool verifyTApasswd(TEE_UUID TA_uuid, char *account, char *password, Cache *cache) {
    //todo: search a ta state from tacache
    //step1: check the queue is or not is empty
    if (cache->head == END_NULL && cache->tail == END_NULL)
    {
         tloge("Failed to get a valid cache!\n");
         return false;
    }
    int32_t front = head;//don not change the original value
    while (front != END_NULL && TA_uuid != cache->ta[front].id)
    {
        //loop
        front = cache->ta->next; //move to next one
    }
    if (front != END_NULL)
    {
        //find the TA_uuid in the cache
        if(!(memcmp(account,cache->ta[front].account) && memcmp(password,cache->ta[front].password)))
        {
            tloge("Failed to verify the TA password!\n");
            return false;
        }
    }
    return true;   

}

void attestTA(TEE_UUID TA_uuid) {
    //attest a ta's trusted station locally by QTA
}
