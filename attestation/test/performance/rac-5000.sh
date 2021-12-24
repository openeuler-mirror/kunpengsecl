#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# run number of rac clients to test
NUM=${NUM:-5}
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
echo "start to perform test ..." | tee -a ${DST}/control.txt
echo "wait for all rac registered..." | tee -a ${DST}/control.txt
for (( i=1; i<=${NUM}; i++))
do
    for (( j=1; j<=360; j++))
    do
        echo -en "\b\b\b\b\b\b\b\b\b${i} ${j}    "
        grep "report ${i}" ${DST}/ras/echo.txt > /dev/null
        if (( $? == 0 ))
        then
            echo -en "\b\b\b\b\b\b\b\b\b${i} done"
            break
        fi
        sleep 1
    done
    if (( ${j} > 3600 ))
    then
        echo -e "\ntimeout, test failed! " | tee -a ${DST}/control.txt
        echo "kill all test processes..." | tee -a ${DST}/control.txt
        pkill -u ${USER} ras
        pkill -u ${USER} raagent
        exit 1
    fi
done

echo -e "\ntest succeeded! " | tee -a ${DST}/control.txt
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
exit 0