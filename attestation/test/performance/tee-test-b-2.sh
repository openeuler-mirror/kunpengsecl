#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
REQNUM=10000
TOTALTIME=0
MAXTIME=0
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh
# . ${PROJROOT}/attestation/test/performance/common-qca.sh
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
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver > ${DST}/qca/echo.out 2>&1 ; )&
# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 20s"  | tee -a ${DST}/control.txt
sleep 20  | tee -a ${DST}/control.txt
# get cid
echo "get client id" | tee -a ${DST}/control.txt
cid=$(awk '{ if ($1 == "clientid:") { print $2 } }' ${DST}/rac-1/config.yaml)
echo ${cid} | tee -a ${DST}/control.txt
echo "get ${REQNUM} times server trust status via restapi request"  | tee -a ${DST}/control.txt
# get restapi auth token from echo.txt
AUTHTOKEN=$(grep "Bearer " ${DST}/ras/echo.txt)
for (( i=1; i<=${REQNUM}; i++ ))
do
    START=$(date +%s%N)/1000000
    RESPONSE=$(curl -k -H "Content-Type: application/json" https://localhost:40003/${cid} -s)
    echo ${RESPONSE} >> ${DST}/control.txt
    END=$(date +%s%N)/1000000
    reqtime=$((END-START))
    TOTALTIME=$((TOTALTIME+reqtime))
    if (( reqtime > MAXTIME ))
    then
        MAXTIME=${reqtime}
        echo "change MAXTIME=${MAXTIME}ms"
    fi
done
echo "It took ${TOTALTIME}ms to get ${REQNUM} times trust status of ${NUM} server, the average time is $((TOTALTIME/REQNUM))ms, the max time is $((MAXTIME))ms." | tee -a ${DST}/control.txt
### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} qcaserver
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt