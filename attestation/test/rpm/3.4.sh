#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### define some constant
strUUID="9b954212d796863e9f2c04372d4ab7e39fe0b62870c82a9e83c3ec326e5fb9b9"
strDEVICE="device"
strNAME="testDevice"
strUNKNOWN="unknown"

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${HOMERACCONF}/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt

# first time query specific client's device trust status
echo "first time query trust status of specific client:${cid} device:${strUUID}..." | tee -a ${DST}/control.txt
STATUSLIST1=$(curl -k -H "Authorization: $AUTHTOKEN" https://localhost:40003/${cid}/device/status)
STATUS1=$(echo ${STATUSLIST1} | grep ${strUUID} | awk '{gsub(/\\n"/,"",$3);print $3}')
if [ -z "${STATUS1}" ]
then
    echo "query device:${strUUID} trust status in database is empty." | tee -a ${DST}/control.txt
    echo "take the next step..." | tee -a ${DST}/control.txt
else
    echo "device:${strUUID} already exists." | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

# add device basevalue
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
echo "start adding new device basevalue which uuid is ${strUUID}..." | tee -a ${DST}/control.txt
curl -X POST -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/${cid}/newbasevalue --data "{\"uuid\":\"${strUUID}\", \"basetype\":\"${strDEVICE}\", \"name\":\"${strNAME}\", \"enabled\":true}"
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

# second time query specific client's device trust status
echo "second time query trust status of specific client:${cid} device:${strUUID}..." | tee -a ${DST}/control.txt
STATUSLIST2=$(curl -k -H "Authorization: $AUTHTOKEN" https://localhost:40003/${cid}/device/status)
STATUS2=$(echo ${STATUSLIST2} | grep ${strUUID} | awk '{gsub(/\\n"/,"",$3);print $3}')
if [ "${STATUS2}" == "${strUNKNOWN}" ]
then
    echo "query device:${strUUID} trust status in database is empty." | tee -a ${DST}/control.txt
    echo "take the next step..." | tee -a ${DST}/control.txt
else
    echo "unexpected trust status!" | tee -a ${DST}/control.txt
    pkill -u ${USER} ras
    pkill -u ${USER} raagent
    echo "test DONE!!!" | tee -a ${DST}/control.txt
    exit 1
fi

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test SUCCEEDED!!!" | tee -a ${DST}/control.txt
exit 0