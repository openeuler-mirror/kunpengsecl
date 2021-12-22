#!/bin/bash
# this is the common part of most integration test scripts, should be included by other scripts as below:
# . ${PROJROOT}/attestation/test/integration/common.sh
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
. ${PROJROOT}/attestation/test/integration/common-def.sh
DST=$(mktemp -t -d ${TESTDIR_PREFIX}-XXXXXX)

# run number of rac clients to test
NUM=${NUM:-1}

echo "=========="
echo "start test ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
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