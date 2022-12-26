#!/bin/bash
# this is the common part of most integration test scripts, should be included by other scripts as below:
# . ${PROJROOT}/attestation/test/integration/common.sh
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
. ${PROJROOT}/attestation/test/integration/common-def.sh
DST=$(mktemp -t -d ${TESTDIR_PREFIX}-XXXXXX)

# run number of rac clients to test
NUM=${NUM:-5}
# run number of attester to test
NUM2=${NUM2:-10}
# run number of qca to test
NUM3=${NUM3:-5}
# run number of ta to test
NUM4=${NUM4:-5}

echo "=========="
echo "start test ${CASENAME} at: $(date)" | tee -a ${DST}/control.txt
echo "prepare the test environments..." | tee -a ${DST}/control.txt

# prepare tbprovisioner
# cp ${TBPRO} ${DST}

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
cp ${TALIST} ${DST}/rac
mkdir -p ${DST}/cert
cp ${CACERT} ${DST}/cert
cp ${KCMCERT} ${DST}/cert
cp ${KCMPRIVKEY} ${DST}/cert
cp ${RACCACERT} ${DST}/rac
cp ${KTACERT} ${DST}/rac
cp ${KTAPRIVKEY} ${DST}/rac
for (( i=1; i<=${NUM}; i++ ))
do
    RACDIR=${DST}/rac-${i}
    mkdir -p ${RACDIR}
    cp ${RACCONF} ${RACDIR}
    ln -s ${DST}/rac/${BIOSFILE} ${RACDIR}
    ln -s ${DST}/rac/${IMAFILE} ${RACDIR}
    ln -s ${DST}/rac/${TALISTFILE} ${RACDIR}
    mkdir -p ${RACDIR}/cert
    ln -s ${DST}/rac/ca.crt ${RACDIR}/cert
    ln -s ${DST}/rac/kta.crt ${RACDIR}/cert
    ln -s ${DST}/rac/kta.key ${RACDIR}/cert
done

# prepare akserver
mkdir -p ${DST}/tas
cp ${TAS} ${DST}/tas
cp ${TASCONF} ${DST}/tas
cp ${CMDTAS}/"Huawei IT Product CA.pem" ${DST}/tas
cp ${TASAUTHKEY} ${DST}/tas

# prepare qcaserver
mkdir -p ${DST}/qca
cp ${QCASERVER} ${DST}/qca
cp ${QCACONF} ${DST}/qca
for i in `seq ${NUM3}`
do
    QCADIR=${DST}/qca-${i}
    mkdir -p ${QCADIR}
    cp ${QCACONF} ${QCADIR}
    (( PORT=50000+${i} ))
    sed -i "s?server: 127.0.0.1:40007?server: 127.0.0.1:${PORT}?g" ${QCADIR}/config.yaml
done

# prepare attester
mkdir -p ${DST}/attester
cp ${ATTESTER} ${DST}/attester
cp ${ATTESTERCONF} ${DST}/attester
cp ${BASEVALUE} ${DST}/attester
for i in `seq ${NUM2}`
do
    ATTESTERDIR=${DST}/attester-${i}
    mkdir -p ${ATTESTERDIR}
    ln -s ${DST}/attester/config.yaml ${ATTESTERDIR}
    ln -s ${DST}/attester/basevalue.txt ${ATTESTERDIR}
done

# prepare authserver
# mkdir -p ${DST}/authserver
# cp ${SAMPLEAUTHSVR} ${DST}/authserver
# cp ${SAMPLEAUTHSVRAUTHKEY} ${DST}/authserver
# cp -rf ${SAMPLEAUTHSVRSTATIC} ${DST}/authserver

# prepare authclient
# mkdir -p ${DST}/authclient
# cp ${SAMPLECLIENT} ${DST}/authclient