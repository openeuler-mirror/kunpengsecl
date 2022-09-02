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
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&
echo "wait for 5s" | tee -a ${DST}/control.txt
sleep 5

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
# set heartbeat cycle to 3s and trust cycle to 10s
echo "set heartbeat cycle to 3s and trust cycle to 10s" | tee -a ${DST}/control.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
curl -X POST -k -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" https://localhost:40003/config --data '{"hbDuration":"3s","trustduration":"10s"}'

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t true -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done
echo "wait for 10s"  | tee -a ${DST}/control.txt
sleep 10  | tee -a ${DST}/control.txt

# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
echo "check server trust status via restapi request"  | tee -a ${DST}/control.txt
RESPONSE1=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
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

echo "wait for 20s" | tee -a ${DST}/control.txt
sleep 20 | tee -a ${DST}/control.txt
echo "check server trust status via restapi request" | tee -a ${DST}/control.txt
# get restapi auth token from echo.txt
# AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
# curl -X POST -H "Authorization: $AUTHTOKEN" -H "Content-Type: application/json" http://localhost:40002/config --data '[{"name":"hbDuration","value":"10s"}]'
RESPONSE2=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid})
echo ${RESPONSE2} | tee -a ${DST}/control.txt

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
STATUS1=$(echo ${RESPONSE1} | jq -r '.' | grep -A 0 "trusted" |  awk -F '"' '{print $4}')
STATUS2=$(echo ${RESPONSE2} | jq -r '.' | grep -A 0 "trusted" |  awk -F '"' '{print $4}')

### generate the test report
echo "First time: Status:${STATUS1}" | tee -a ${DST}/control.txt
echo "Second time: Status:${STATUS2}" | tee -a ${DST}/control.txt
if [[ ${STATUS1} == "trusted"  && ${STATUS2} == "untrusted" ]]
then
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
