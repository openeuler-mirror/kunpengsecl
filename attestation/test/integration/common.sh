#!/bin/bash
# this is the common part of most integration test scripts, should be included by other scripts as below:
# . ${PROJROOT}/attestation/test/integration/common.sh
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
DST=$(mktemp -t -d kunpengsecl-test-XXXXXX)

RACPKG=${PROJROOT}/attestation/rac/pkg
RAAGENT=${RACPKG}/raagent
RAHUB=${RACPKG}/rahub
TBPRO=${RACPKG}/tbprovisioner

CMDRAAGENT=${PROJROOT}/attestation/rac/cmd/raagent
CMDRAHUB=${PROJROOT}/attestation/rac/cmd/rahub
RACCONF=${CMDRAAGENT}/config.yaml
RAHUBCONF=${CMDRAHUB}/config.yaml
BIOSFILE=binary_bios_measurements
IMAFILE=ascii_runtime_measurements
BIOSMANIFEST=${CMDRAAGENT}/${BIOSFILE}
IMAMANIFEST=${CMDRAAGENT}/${IMAFILE}

RAS=${PROJROOT}/attestation/ras/pkg/ras
RASCONF=${PROJROOT}/attestation/ras/cmd/ras/config.yaml
RASAUTHKEY=${PROJROOT}/attestation/ras/cmd/ras/ecdsakey.pub

EXAMPLE=${PROJROOT}/attestation/ras/example
SAMPLEAUTHSVR=${EXAMPLE}/pkg/server
SAMPLECLIENT=${EXAMPLE}/pkg/client
SAMPLEAUTHSVRAUTHKEY=${EXAMPLE}/sampleauthserver/ecdsakey
SAMPLEAUTHSVRSTATIC=${EXAMPLE}/sampleauthserver/static

# run number of rac clients to test
# NUM=1

echo "start test at: $(date)" > ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

# prepare tbprovisioner
cp ${TBPRO} ${DST}

# prepare ras
mkdir -p ${DST}/ras
cp ${RAS} ${DST}/ras
cp ${RASCONF} ${DST}/ras
cp ${RASAUTHKEY} ${DST}/ras

# prepare rahub
mkdir -p ${DST}/hub
cp ${RAHUB} ${DST}/hub
cp ${RAHUBCONF} ${DST}/hub

# prepare raagent
mkdir -p ${DST}/rac
cp ${RAAGENT} ${DST}/rac
cp ${BIOSMANIFEST} ${DST}/rac
cp ${IMAMANIFEST} ${DST}/rac
for (( i=1; i<=${NUM}; i++ ))
do
    RACDIR=${DST}/rac-${i}
    mkdir -p ${RACDIR}
    cp ${RACCONF} ${RACDIR}
    ln -s ${DST}/rac/${BIOSFILE} ${RACDIR}
    ln -s ${DST}/rac/${IMAFILE} ${RACDIR}
done

# prepare authserver
mkdir -p ${DST}/authserver
cp ${SAMPLEAUTHSVR} ${DST}/authserver
cp ${SAMPLEAUTHSVRAUTHKEY} ${DST}/authserver
cp -rf ${SAMPLEAUTHSVRSTATIC} ${DST}/authserver

# prepare authclient
mkdir -p ${DST}/authclient
cp ${SAMPLECLIENT} ${DST}/authclient

FILENAME=`basename $0`
# DIRNAME=`dirname $0`
CASENAME=${FILENAME%.*}
# echo ${FILENAME%.*}, ${FILENAME##*.}