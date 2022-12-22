#!/bin.bash
### this scripts should be run under the root folder of kunpengsecl project
PROJROOT=.
MEASURE0="TEE Measurement: 0"
MEASURE1="TEE Measurement: 1"
MEASURE2="TEE Measurement: 2"
MEASURE3="TEE Measurement: 3"

# include common part
. ${PROJROOT}/attestation/test/tee/integration/common.sh
echo "=========="
echo "start ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

echo "start akservice..." | tee -a ${DST}/control.txt
( cd ${DST}/tas ; ./akserver -T &>${DST}/tas/echo.txt ; ./akserver &>>${DST}/tas/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start qca demo..." | tee -a ${DST}/control.txt
( cd ${DST}/qca ; ./qcaserver -C 2 &>${DST}/qca/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start attester demo the first time..." | tee -a ${DST}/control.txt
( cd ${DST}/attester ; ./attester -T -M 1 &>${DST}/attester/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill attester demo process..." | tee -a ${DST}/control.txt
pkill -u ${USER} attester
S1=$(cat ${DST}/attester/echo.txt | grep "${MEASURE1}")
if [ ! -z "${S1}" ]; then
    echo "using measurement policy 1 succeeded" | tee -a ${DST}/control.txt
else
    echo "using measurement policy 1 failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start attester demo the second time..." | tee -a ${DST}/control.txt
( cd ${DST}/attester ; ./attester -T -M 2 &>>${DST}/attester/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill attester demo process..." | tee -a ${DST}/control.txt
pkill -u ${USER} attester
S2=$(cat ${DST}/attester/echo.txt | grep "${MEASURE2}")
if [ ! -z "${S2}" ]; then
    echo "using measurement policy 2 succeeded" | tee -a ${DST}/control.txt
else
    echo "using measurement policy 2 failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start attester demo the third time..." | tee -a ${DST}/control.txt
( cd ${DST}/attester ; ./attester -T -M 3 &>>${DST}/attester/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill attester demo process..." | tee -a ${DST}/control.txt
pkill -u ${USER} attester
S3=$(cat ${DST}/attester/echo.txt | grep "${MEASURE3}")
if [ ! -z "${S3}" ]; then
    echo "using measurement policy 3 succeeded" | tee -a ${DST}/control.txt
else
    echo "using measurement policy 3 failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "start attester demo the last time..." | tee -a ${DST}/control.txt
( cd ${DST}/attester ; ./attester -T -M 0 &>>${DST}/attester/echo.txt ; )&
echo "wait for 3s..." | tee -a ${DST}/control.txt
sleep 3

echo "kill all processes..." | tee -a ${DST}/control.txt
pkill -u ${USER} akserver
pkill -u ${USER} qcaserver
pkill -u ${USER} attester
S4=$(cat ${DST}/attester/echo.txt | grep "${MEASURE0}")
if [ ! -z "${S4}" ]; then
    echo "using measurement policy 0 succeeded" | tee -a ${DST}/control.txt
    echo "test succeeded!" | tee -a ${DST}/control.txt
    exit 0
else
    echo "using measurement policy 0 failed" | tee -a ${DST}/control.txt
    echo "test failed!" | tee -a ${DST}/control.txt
    exit 1
fi