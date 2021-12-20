#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
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
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras &>>${DST}/ras/echo.txt ;)&

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ${TEST_ID}..." | tee -a ${DST}/control.txt
echo "wait for 5s"
sleep 5
echo "check server trust status via restapi request"
# get restapi auth token from echo.txt
# AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
# curl -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"10s"}]'
RESPONSE1=$(curl http://localhost:40002/status 2>/dev/null)
echo ${RESPONSE1} | tee -a ${DST}/control.txt
# stop rac
echo "kill all raagent processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent

# modify ima file
OLDLINE="10 6fefbefdf63fbc4210a8eee66a21a63e578300d6 ima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca \/etc\/modprobe.d\/tuned.conf"
NEWLINE="10 88ff8c85e6b94cbf8002a17fd59f1ea1bd13ecc4 ima 2b8ccbdcaac1956b7c48529efbfb32e76355b1ca \/etc\/modprobe.d\/tuned.conf"
sed -i --follow-symlinks "s/${OLDLINE}/${NEWLINE}/g" ${RACDIR}/${IMAFILE}

# start number of rac 
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

echo "wait for 90s"
sleep 90
echo "check server trust status via restapi request"
# get restapi auth token from echo.txt
# AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
# curl -X POST -H "Authorization: $TOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"10s"}]'
RESPONSE2=$(curl http://localhost:40002/status 2>/dev/null)
echo ${RESPONSE2} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
CLIENTID1=$(echo ${RESPONSE1} | jq -r '.' | awk '/ClientID/ {gsub(",","",$2);print $2}')
STATUS1=$(echo ${RESPONSE1} | jq -r '.' | awk '/Status/ {gsub(",","",$2);gsub("\"","",$2);print $2}')
CLIENTID2=$(echo ${RESPONSE2} | jq -r '.' | awk '/ClientID/ {gsub(",","",$2);print $2}')
STATUS2=$(echo ${RESPONSE2} | jq -r '.' | awk '/Status/ {gsub(",","",$2);gsub("\"","",$2);print $2}')

### generate the test report
echo "First time: ClientID:${CLIENTID1}, Status:${STATUS1}"
echo "Second time: ClientID:${CLIENTID2}, Status:${STATUS2}"
if [[ ${STATUS1} == "trusted"  && ${STATUS2} == "untrusted" ]]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
