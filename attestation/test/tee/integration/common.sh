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