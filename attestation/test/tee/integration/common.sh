#!/bin/bash
### this script is used to generate aks certificate and private key

FILENAME=`basename $0`
CASENAME=${FILENAME%.*}

TESTDIR_PREFIX=${TESTDIR_PREFIX:-kunpengsecl-tas-test}
DST=$(mktemp -t -d ${TESTDIR_PREFIX}-XXXXXX)

TASPKG=${PROJROOT}/attestation/tas/pkg
TEEPKG=${PROJROOT}/attestation/tee/demo/pkg
CMDAKSERVICE=${PROJROOT}/attestation/tas/cmd
CMDQCASERVER=${PROJROOT}/attestation/tee/demo/qca_demo/cmd
CMDATTESTER=${PROJROOT}/attestation/tee/demo/attester_demo/cmd

AKSERVICE=${TASPKG}/akserver
AKSCONF=${CMDAKSERVICE}/config.yaml
AKSCERT=${DST}/tas/ascert.crt

QCASERVER=${TEEPKG}/qcaserver
QCACONF=${CMDQCASERVER}/config.yaml
NODAACERT=${DST}/qca/nodaa-ac.crt
DAACERT=${DST}/qca/daa-ac.crt

ATTESTER=${TEEPKG}/attester
ATTESTERCONF=${CMDATTESTER}/config.yaml
BASEVALUE=${CMDATTESTER}/basevalue.txt
DAAPUBKEY=${CMDATTESTER}/daa-pubkey

# prepare akservice
mkdir -p ${DST}/tas
cp ${AKSERVICE} ${DST}/tas
cp ${CMDAKSERVICE}/"Huawei IT Product CA".pem ${DST}/tas
cp ${AKSCONF} ${DST}/tas
pushd $(pwd)
cd ${DST}/tas
openssl genrsa -out aspriv.key 4096
openssl rsa -in aspriv.key -pubout -out aspub.key
openssl req -new -x509 -days 365 -key aspriv.key -out ascert.crt
popd

# prepare qcaserver
mkdir -p ${DST}/qca
cp ${QCASERVER} ${DST}/qca
cp ${QCACONF} ${DST}/qca

# prepare attester
mkdir -p ${DST}/attester
cp ${ATTESTER} ${DST}/attester
cp ${ATTESTERCONF} ${DST}/attester
cp ${BASEVALUE} ${DST}/attester
cp ${AKSCERT} ${DST}/attester
cp ${DAAPUBKEY} ${DST}/attester

CERTFILE=${PROJROOT}/attestation/ras/cert
RAS=${PROJROOT}/attestation/ras/pkg/ras
CACERT=${CERTFILE}/ca.crt
KCMCERT=${CERTFILE}/kcm.crt
KCMPRIVKEY=${CERTFILE}/kcm.key
RASCONF=${PROJROOT}/attestation/ras/cmd/config.yaml
RASAUTHKEY=${PROJROOT}/attestation/ras/cmd/ecdsakey.pub

# prepare ras
mkdir -p ${DST}/ras
cp ${RAS} ${DST}/ras
cp ${RASCONF} ${DST}/ras
cp ${RASAUTHKEY} ${DST}/ras

CMDRAAGENT=${PROJROOT}/attestation/rac/cmd/raagent
RACPKG=${PROJROOT}/attestation/rac/pkg
RAAGENT=${RACPKG}/raagent
RACCONF=${CMDRAAGENT}/config.yaml
BIOSFILE=binary_bios_measurements
IMAFILE=ascii_runtime_measurements
TALISTFILE=talist
BIOSMANIFEST=${CMDRAAGENT}/${BIOSFILE}
IMAMANIFEST=${CMDRAAGENT}/${IMAFILE}
TALIST=${CMDRAAGENT}/${TALISTFILE}
RACCACERT=${CMDRAAGENT}/cert/ca.crt
KTACERT=${CMDRAAGENT}/cert/kta.crt
KTAPRIVKEY=${CMDRAAGENT}/cert/kta.key

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

# prepare demo_ca & demo_ta
DEMOCA=${PROJROOT}/attestation/tee/demo/demo_ca
mkdir -p ${DST}/demo_ca
# cp -rf $DEMOCA ${DST}/demo_ca
cp -f /root/iTrustee_Cloud_SDK_for_ta/test/CA/demo_ca/demo_ca ${DST}/demo_ca