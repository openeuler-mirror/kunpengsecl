#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=1
# include common part
. ${PROJROOT}/attestation/test/tee/integration/common.sh
# above are common preparation steps, below are specific preparation step, scope includs:
# configure files, input files, environment variables, cmdline paramenters, flow control paramenters, etc.

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; /usr/bin/raagent -t -v -k &>${DST}/rac-${i}/echo.txt ; )&
    cp -r ${KTACERT} ${DST}/rac-${i}
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

COUNT=$(grep 'ka initialize done' ${DST}/rac-1/echo.txt |wc -l)
echo "count: ${COUNT}" | tee -a ${DST}/control.txt
### list the log
### tail -f ${DST}/rac-1/echo.txt
if (( ${COUNT} == 1 ))
then
    echo "test succeeded!"
    exit 0
else
    echo "test failed!"
    exit 1
fi
