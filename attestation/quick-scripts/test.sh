#!/bin/bash

#set -eux
DST=/tmp/kunpengsecl-test
RACPKG=./attestation/rac/pkg
RAAGENT=${RACPKG}/raagent
RACCONF=./attestation/rac/cmd/raagent/config.yaml
RAHUB=${RACPKG}/rahub
TBPRO=${RACPKG}/tbprovisioner
RAS=./attestation/ras/pkg/ras
RASCONF=./attestation/ras/config/config.yaml
# run number of rac clients to test
NUM=5

rm -rf ${DST}
mkdir -p ${DST}
cp ${TBPRO} ${DST}
mkdir -p ${DST}/ras
cp ${RAS} ${DST}/ras
cp ${RASCONF} ${DST}/ras
mkdir -p ${DST}/hub
cp ${RAHUB} ${DST}/hub
for (( i=1; i<=${NUM}; i++ ))
do
    RACDIR=${DST}/rac-${i}
    mkdir -p ${RACDIR}
    cp ${RAAGENT} ${RACDIR}
    cp ${RACCONF} ${RACDIR}
done

( cd ${DST}/ras ; ./ras &>${DST}/ras/log.txt ; )&
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ./raagent &>${DST}/rac-${i}/log.txt ; )&
done

