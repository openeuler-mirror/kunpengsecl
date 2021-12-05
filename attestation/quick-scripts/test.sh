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

( cd ${DST}/ras ; ./ras &>${DST}/ras/log.txt ; )&
for (( i=1; i<=${NUM}; i++ ))
do
    ( cd ${DST}/rac-${i} ; ${DST}/rac/raagent -t &>${DST}/rac-${i}/log.txt ; )&
done

