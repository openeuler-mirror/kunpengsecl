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
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo1.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

### start monitoring and control the testing
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for 60s" | tee -a ${DST}/control.txt
sleep 60
echo "kill rac processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} raagent
### launching rahub for testing
echo "start rahub..." | tee -a ${DST}/control.txt
( cd ${DST}/hub ; ./rahub &>${DST}/hub/echo.txt ;)&
# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v -s 127.0.0.1:40003 &>${DST}/rac-${i}/echo2.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done
echo "wait for 60s" | tee -a ${DST}/control.txt
sleep 60

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} rahub
pkill -u ${USER} raagent

echo "test DONE!!!" | tee -a ${DST}/control.txt

### analyse the testing data
echo "please collect the data from ${DST}/rac-1/echo1.txt & ${DST}/rac-1/echo2.txt and do the ongoing analysis."

