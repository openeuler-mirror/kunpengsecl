#!/bin/bash

set -eux
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

( cd ${DST}/ras ; ./ras &>${DST}/ras/log.txt ; )&
( cd ${DST}/authserver ; ./server &>${DST}/authserver/log.txt ; )&
( cd ${DST}/authclient ; ./client &>${DST}/authclient/log.txt ; )&

for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>${DST}/rac-${i}/log.txt ; )&
done

