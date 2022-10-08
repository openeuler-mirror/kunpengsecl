#!/bin/bash
# this is the common part of most integration test scripts, should be included by other scripts as below:
# . ${PROJROOT}/attestation/test/rpm/common.sh
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
### define some constants
FILENAME=`basename $0`
CASENAME=${FILENAME%.*}
TESTDIR_PREFIX=${TESTDIR_PREFIX:-kunpengsecl-test}
DST=$(mktemp -t -d ${TESTDIR_PREFIX}-XXXXXX)
PRORAS=kunpengsecl-ras
PRORAC=kunpengsecl-rac
PROHUB=kunpengsecl-rahub
HOMERASCONF=${HOME}/.config/attestation/ras
HOMERACCONF=${HOME}/.config/attestation/rac
HOMEHUBCONF=${HOME}/.config/attestation/rahub
SHARETAR=/usr/share/attestation
IMAFILE=/sys/kernel/security/ima/ascii_runtime_measurements

### prepare program running environment
echo "=========="
echo "start test ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt
yum remove -y ${PRORAS} ${PRORAC} ${PROHUB}
rm -rf ${HOMERASCONF}/config.yaml ${HOMERACCONF}/config.yaml ${HOMEHUBCONF}/config.yaml
yum install -y ${PRORAS} ${PRORAC} ${PROHUB}
cd ${SHARETAR}/ras
bash prepare-database-env.sh | tee -a ${DST}/control.txt
bash prepare-rasconf-env.sh | tee -a ${DST}/control.txt
bash clear-database.sh | tee -a ${DST}/control.txt
cd ${SHARETAR}/rac
bash prepare-racconf-env.sh | tee -a ${DST}/control.txt
cd ${SHARETAR}/rahub
bash prepare-hubconf-env.sh | tee -a ${DST}/control.txt
cd ${HOMERASCONF}
sed -i 's/digestalgorithm: sha1/digestalgorithm: sha256/g' config.yaml
sed -i '/\/etc\/modprobe.d\/tuned.conf/d' config.yaml
mkdir -p ${DST}/ras ${DST}/hub ${DST}/rac
echo "The initialization program running environment is complete!" | tee -a ${DST}/control.txt
echo "=========="
