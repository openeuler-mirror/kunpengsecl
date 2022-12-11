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
extern Cache cache;
extern CmdQueue cmdqueue;
extern ReplyCache replycache;
//check the id1 and the id2 equal
bool CheckUUID(TEE_UUID id1,TEE_UUID id2)
{
    if(id1.timeHiAndVersion != id2.timeHiAndVersion || 
    id1.timeLow != id2.timeLow ||
    id1.timeMid != id2.timeMid){
        return false;
    }
    for(int32_t i = 0;i < NODE_LEN; i++){
        if(id1.clockSeqAndNode[i] != id2.clockSeqAndNode[i]){
            return false;
        }
    }
    return true;
}
bool verifyTApasswd(TEE_UUID TA_uuid, char *account, char *password) {
    //todo: search a ta state from tacache
    //step1: check the queue is or not is empty
    if (cache.head == END_NULL && cache.tail == END_NULL)
    {
         tloge("Failed to get a valid cache!\n");
         return false;
    }
    //step2: find the TA_uuid from the cache
    int32_t front = cache.head;//don not change the original value
    while (front != END_NULL && !CheckUUID(TA_uuid,cache.ta[front].id))
    {
        //loop
        front = cache.ta->next; //move to next one
    }
    ////step3: compare the cache's value with account and password
    if (front != END_NULL)
    {
        //find the TA_uuid in the cache
        if(!(memcmp(account,cache.ta[front].account,sizeof(cache.ta[front].account)) 
        && memcmp(password,cache.ta[front].password,sizeof(cache.ta[front].password))))
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
