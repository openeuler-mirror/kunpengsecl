#!/bin/bash

#set -eux
DST=/tmp/kunpengsecl-test
RACPKG=./attestation/rac/pkg
RAAGENT=${RACPKG}/raagent
RACCONF=./attestation/rac/cmd/raagent/config.yaml
BIOSMANIFESTNAME=binary_bios_measurements
IMAMANIFESTNAME=ascii_runtime_measurements
BIOSMANIFEST=./attestation/rac/cmd/raagent/${BIOSMANIFESTNAME}
IMAMANIFEST=./attestation/rac/cmd/raagent/${IMAMANIFESTNAME}
RAHUB=${RACPKG}/rahub
TBPRO=${RACPKG}/tbprovisioner
RAS=./attestation/ras/pkg/ras
RASCONF=./attestation/ras/cmd/ras/config.yaml
RASAUTHKEY=./attestation/ras/cmd/ras/ecdsakey.pub
EXAMPLE=./attestation/ras/example
SAMPLEAUTHSVR=${EXAMPLE}/pkg/server
SAMPLEAUTHSVRAUTHKEY=${EXAMPLE}/sampleauthserver/ecdsakey
SAMPLEAUTHSVRSTATIC=${EXAMPLE}/sampleauthserver/static
SAMPLECLIENT=${EXAMPLE}/pkg/client
# run number of rac clients to test
NUM=5

# check number times the performance
NUMPFM=60


echo "start test at: $(date)" > ${DST}/perf.txt
echo "prepare the test environments..." | tee -a ${DST}/perf.txt
rm -rf ${DST}
mkdir -p ${DST}
cp ${TBPRO} ${DST}
mkdir -p ${DST}/ras
cp ${RAS} ${DST}/ras
cp ${RASCONF} ${DST}/ras
cp ${RASAUTHKEY} ${DST}/ras
mkdir -p ${DST}/hub
cp ${RAHUB} ${DST}/hub
mkdir -p ${DST}/rac
cp ${RAAGENT} ${DST}/rac
cp ${BIOSMANIFEST} ${DST}/rac
cp ${IMAMANIFEST} ${DST}/rac
for (( i=1; i<=${NUM}; i++ ))
do
    RACDIR=${DST}/rac-${i}
    mkdir -p ${RACDIR}
    cp ${RACCONF} ${RACDIR}
    ln -s ${DST}/rac/${BIOSMANIFESTNAME} ${RACDIR}/${BIOSMANIFESTNAME}
    ln -s ${DST}/rac/${IMAMANIFESTNAME} ${RACDIR}/${IMAMANIFESTNAME}
done
mkdir -p ${DST}/authserver
cp ${SAMPLEAUTHSVR} ${DST}/authserver
cp ${SAMPLEAUTHSVRAUTHKEY} ${DST}/authserver
cp -rf ${SAMPLEAUTHSVRSTATIC} ${DST}/authserver
mkdir -p ${DST}/authclient
cp ${SAMPLECLIENT} ${DST}/authclient

echo "start ras..." | tee -a ${DST}/perf.txt
( cd ${DST}/ras ; ./ras &>${DST}/ras/echo.txt ; )&
echo "start rahub..." | tee -a ${DST}/perf.txt
( cd ${DST}/hub ; ./rahub &>${DST}/hub/echo.txt ; )&
echo "start authserver..." | tee -a ${DST}/perf.txt
( cd ${DST}/authserver ; ./server &>${DST}/authserver/echo.txt ; )&
echo "start authclient..." | tee -a ${DST}/perf.txt
( cd ${DST}/authclient ; ./client &>${DST}/authclient/echo.txt ; )&

# start number of rac clients
echo "start ${NUM} rac clients..." | tee -a ${DST}/perf.txt
(( count=0 ))
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>${DST}/rac-${i}/echo.txt ; )&
    (( count++ ))
    if (( count >= 1 ))
    then
        (( count=0 ))
        echo "start ${i} rac clients at $(date)..." | tee -a ${DST}/perf.txt
        top -b -n 1 | awk '/load/ {print $10, $11, $12, $13, $14}' | tee -a ${DST}/perf.txt
    fi
done

# check number times of performance and record
echo "start to check performance..." | tee -a ${DST}/perf.txt
for (( i=1; i<=${NUMPFM}; i++ ))
do
    echo "check ${i} at: $(date)" | tee -a ${DST}/perf.txt
    top -b -n 1 | awk '/load/ {print $10, $11, $12, $13, $14}' | tee -a ${DST}/perf.txt
    top -b -n 1 | awk '/ras/ {print $12, $1, $9, $10, $6}' | tee -a ${DST}/perf.txt
    top -b -n 1 | awk '/rahub/ {print $12, $1, $9, $10, $6}' | tee -a ${DST}/perf.txt
    top -b -n 1 | awk '/raagent/ {print $12, $1, $9, $10, $6}' | tee -a ${DST}/perf.txt
    top -b -n 1 | awk '/post/ {print $12, $1, $9, $10, $6}' | tee -a ${DST}/perf.txt
    sleep 1
done

echo "kill all test processes..." | tee -a ${DST}/perf.txt
pkill -u ${USER} ras
pkill -u ${USER} raagent
pkill -u ${USER} rahub
pkill -u ${USER} server
pkill -u ${USER} client

echo "test DONE!!!" | tee -a ${DST}/perf.txt
