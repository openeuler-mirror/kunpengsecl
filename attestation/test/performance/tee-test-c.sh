#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
# include common part
. ${PROJROOT}/attestation/test/integration/common.sh
NUM=1
SENDREQUEST="prepare to encrypt data"
MISSRESPONSE="get a key generate reply"
HITRESPONSE="success to search key"
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
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "prepare kcm enviroment..." | tee -a ${DST}/control.txt
sh prepare-kcm-env.sh | tee -a ${DST}/control.txt
popd
echo "start ras..." | tee -a ${DST}/control.txt
( cd /root/kunpengsecl/attestation/ras/cmd ; /root/kunpengsecl/attestation/ras/pkg/ras -T &>${DST}/ras/echo.txt ; /root/kunpengsecl/attestation/ras/pkg/ras -v &>>${DST}/ras/echo.txt ; )&
echo "start qcaserver..." | tee -a ${DST}/control.txt
( cd /root/kunpengsecl/attestation/rac/cmd/raagent ; /root/kunpengsecl/attestation/tee/demo/pkg/qcaserver &>${DST}/qca/echo.txt ; )&
### start number of rac clients
( cd /root/kunpengsecl/attestation/rac/cmd/raagent ; /usr/bin/raagent -t -v -k -S &>${DST}/rac/echo.txt ; )&
pushd $(pwd)
cd ${PROJROOT}/attestation/quick-scripts
echo "prepare kcm enviroment..." | tee -a ${DST}/control.txt
sh prepare-kcm-env.sh | tee -a ${DST}/control.txt
popd
echo "start ${NUM} rac clients..." | tee -a ${DST}/control.txt
( cd /root/kunpengsecl/attestation/rac/cmd/raagent ; /usr/bin/raagent -t -v -k &>>${DST}/rac/echo.txt ; )&
### start demo_ca & demo_ta
echo "start demo_ca & demo_ta..." | tee -a ${DST}/control.txt
mkdir ${DST}/demo
( /root/vendor/bin/demo_ca &>${DST}/demo/echo.txt ; )&

echo "wait for 10s..." | tee -a ${DST}/control.txt
sleep 10

### stop testing
echo "kill all test processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} ras
pkill -u ${USER} qcaserver
pkill -u ${USER} raagent

REQ1=$(cat /var/log/tee/LOG\@BBB2D138EE2143AF879640C20D7B45FA-0 | awk '/138:prepare to encrypt data/ {print $3}' | sed -n '5p')
REQTIME1=$(($(date +%s%N -d "${REQ1}")/1000000))
RES1=$(cat /var/log/tee/LOG\@BBB2D138EE2143AF879640C20D7B45FA-0 | awk '/256:get a key generate reply/ {print $3}')
RESTIME1=$(($(date +%s%N -d "${RES1}")/1000000))
REQ2=$(cat /var/log/tee/LOG\@BBB2D138EE2143AF879640C20D7B45FA-0 | awk '/138:prepare to encrypt data/ {print $2}' | sed -n '6p')
REQTIME2=$(($(date +%s%N -d "${REQ2}")/1000000))
RES2=$(cat /var/log/tee/LOG\@BBB2D138EE2143AF879640C20D7B45FA-0 | awk '/107:success to search key/ {print $2}')
RESTIME2=$(($(date +%s%N -d "${RES2}")/1000000))
MISSTIME=$((${RESTIME1} - ${REQTIME1}))
HITTIME=$((${RESTIME2} - ${REQTIME2}))

if [ ${MISSTIME} -lt 5000 ] && [ ${HITTIME} -lt 100 ]
then
    echo "the time taken when the key is missed is ${MISSTIME}ms" | tee -a ${DST}/control.txt
    echo "the time taken when the key is hited is ${HITTIME}ms" | tee -a ${DST}/control.txt
    echo "time consumption is acceptable" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 1
else
    echo "the time taken when the key is missed is ${MISSTIME}ms" | tee -a ${DST}/control.txt
    echo "the time taken when the key is hited is ${HITTIME}ms" | tee -a ${DST}/control.txt
    echo "time consumption is unacceptable" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 0
fi
