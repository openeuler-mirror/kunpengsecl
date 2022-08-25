#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=5
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh

# above are common preparation steps, below are specific preparation step, scope includs:
# configure files, input files, environment variables, cmdline paramenters, flow control paramenters, etc.
### Start Preparation
echo "start test preparation..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "clean database" | tee -a ${DST}/control.txt
sh clear-database.sh | tee -a ${DST}/control.txt
popd
### End Preparation

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 3s"
sleep 3
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
# start rahub
echo "start rahub..." | tee -a ${DST}/control.txt
( cd ${DST}/hub ; ./rahub -v &>>${DST}/hub/echo.txt ;)&
echo "wait for 3s"
sleep 3

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -v -t -s 127.0.0.1:40004 &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 20s"
sleep 20
echo "check how many clients are registered via restapi request"

RESPONSE=$(curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/)
echo ${RESPONSE} | tee -a ${DST}/control.txt
CLIENTNUM=$(echo $RESPONSE | jq -r '.' | awk '/id/ {gsub(",","",$2);print $2}' | wc -l | awk '{print $1}')
echo ${CLIENTNUM}
REPORT=$(curl -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/1/reports)
### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
pkill -u ${USER} rahub
echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
# hubmessage=$(cat ${DST}/hub/echo.txt | awk '/rahub: receive SendReport/ {print $1}')
# rasmessage=$(cat ${DST}/ras/echo.txt | awk '/Server: receive SendReport/ {print $1}')
racmessage=$(cat ${DST}/rac-$((i-1))/echo.txt  | awk '/send trust report ok/ {print $1}')

### generate the test report
if [ "${CLIENTNUM}" -eq 5 ] && [ "${racmessage}" != "" ] && [ "${REPORT}" != "[]" ]
then
    echo "all clients are registered!" | tee -a ${DST}/control.txt
    echo "rahub is functioning normally!" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
