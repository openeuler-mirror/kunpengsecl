#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh

# judgement string
RACREGISTER="register client success"

# above are common preparation steps, below are specific preparation step, scope includs:
# configure files, input files, environment variables, cmdline paramenters, flow control paramenters, etc.
### Start Preparation
echo "start test preparation..." | tee -a ${DST}/control.txt
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "clean database" | tee -a ${DST}/control.txt
sh clear-database.sh | tee -a ${DST}/control.txt
popd

#reduce the test ima manifest size
if (( SPEEDUP == 1 ))
then
    IMALINE1="10 24b06bd44d31787e126c471843e9ef2c6345a5da ima 5e7bbf27b7dd568610cc1f1ea49ceaa420395690 boot_aggregate"
    IMALINE2="10 6fefbefdf63fbc4210a8eee66a21a63e578300d6 ima 1b8ccbdcaac1956b7c48529efbfb32e76355b1ca /etc/modprobe.d/tuned.conf"
    echo $IMALINE1 > ${DST}/rac/${IMAFILE}
    echo $IMALINE2 >> ${DST}/rac/${IMAFILE}
    echo "reduce ima manifest to 2 lines to speed up testing" | tee -a ${DST}/control.txt
fi
### End Preparation

### start launching binaries for testing
echo "start ras..." | tee -a ${DST}/control.txt
( cd ${DST}/ras ; ./ras -T &>${DST}/ras/echo.txt ; ./ras -v &>>${DST}/ras/echo.txt ;)&

echo "start qcaserver and generate AK/AKCert..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver &> ${DST}/qca/echo.txt ; )&

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t -v &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 100 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/control.txt
    fi
done

sleep 10

echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} qcaserver
pkill -u ${USER} raagent

sleep 10

echo "wait for all rac registered..." | tee -a ${DST}/control.txt

for (( i=1; i<=${NUM}; i++ ))
do
    if [ `grep -c "${RACREGISTER}" ${DST}/rac-${i}/echo.txt` -eq '0' ] ; then
        echo "test failed!" | tee -a ${DST}/control.txt
        exit 0
    fi
done

echo "test succeeded!" | tee -a ${DST}/control.txt
exit 1
