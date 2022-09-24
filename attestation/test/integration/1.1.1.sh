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
echo "wait for 5s"
sleep 5
### restart the rac
echo "kill all test processes of rac..."
pkill -u ${USER} raagent

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
echo "wait for 5s"
sleep 5

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
echo "test DONE!!!" | tee -a ${DST}/control.txt

### check the ek cert's log is only one
### cat ${DST}/rac-1/echo.txt|grep 'ok' |wc -l
ECCOUNT=$(grep 'load EK certificate success' ${DST}/rac-1/echo.txt |wc -l)
echo "generateEKCert count: ${ECCOUNT}" | tee -a ${DST}/control.txt
### list the log
### tail -f ${DST}/rac-1/echo.txt
### check the ekCert's file is not null
if test -s ${DST}/rac-1/ectest.crt;then
    ECEMPTY=0
    echo "ectest is not empty" | tee -a ${DST}/control.txt
else
    ECEMPTY=1
    echo "ectest is empty" | tee -a ${DST}/control.txt
fi
### check the ik cert's log is only one
ICCOUNT=$(grep 'load IK certificate success' ${DST}/rac-1/echo.txt |wc -l)
echo "generateIKCert count: ${ICCOUNT}" | tee -a ${DST}/control.txt
### check the ekCert's file is not null

if test -s ${DST}/rac-1/ictest.crt;then
    ICEMPTY=0
    echo "ictest is not empty" | tee -a ${DST}/control.txt
else
    ICEMPTY=1
    echo "ictest is empty" | tee -a ${DST}/control.txt
fi

if (( ${ECCOUNT} == 1 )) && (( ${ICCOUNT} == 1 )) && (( ${ECEMPTY} == 0 )) && (( ${ICEMPTY} == 0 ))
then
    echo "test succeeded!"
    exit 0
else
    echo "test failed!"
    exit 1
fi