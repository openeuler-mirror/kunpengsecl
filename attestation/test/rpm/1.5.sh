#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
. ${PROJROOT}/attestation/test/rpm/common.sh

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt

### start ras
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ras -T &>${DST}/ras/echo.txt ; ras -v -H false &>>${DST}/ras/echo.txt ;)&
echo "wait for 3s" | tee -a ${DST}/control.txt
sleep 3
# change config
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '{"trustDuration":"15s"}'

### start rac
echo "start rac at $(date)..." | tee -a ${DST}/control.txt
( cd ${DST}/rac ; sudo raagent -v &>${DST}/rac/echo.txt ; )&
echo "wait for 5s"
sleep 5

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 3s" | tee -a ${DST}/control.txt
sleep 3
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${HOMERACCONF}/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
# get restapi auth token from echo.txt
# CONFIGRESPONSE=$(curl http://localhost:40002/config)
# echo $CONFIGRESPONSE
reporturl="http://localhost:40002/${cid}/reports"
# repeat test for 3 times
TESTTIMES=3
export OLDREPORTID=0
for (( i=1; i<=${TESTTIMES}; i++ ))
do
    # do not use REPORTRESPONSE=$(curl -X GET ${reporturl}), it cost too many memory and may cause mistake
    REPORTID=$(curl -H "Content-Type: application/json" ${reporturl} | jq -r '.' | grep -A 0 "ID" | grep -v "ClientID\|--"  | awk '{gsub(",","",$2);print $2}' | tail -n 1)
    echo "the newest report id is ${REPORTID}" | tee -a ${DST}/control.txt
    echo "the old report id is ${OLDREPORTID}" | tee -a ${DST}/control.txt
    if [ "${REPORTID}" -gt "${OLDREPORTID}" ]
    then
        echo "${i} test successed" | tee -a ${DST}/control.txt
    else
        echo "${i} test failed" | tee -a ${DST}/control.txt
        echo "kill all test processes..." | tee -a ${DST}/control.txt
        pkill -u ${USER} ras
        pkill -u ${USER} raagent
        exit 1
    fi
    OLDREPORTID=${REPORTID}
    # wait 20s for recording new report
    if [ "${i}" -lt "${TESTTIMES}" ] 
    then
        sleep 20
    fi
done
### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "test DONE!!!" | tee -a ${DST}/control.txt