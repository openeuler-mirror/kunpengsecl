#!/bin/bash
# this is the common part of most integration test scripts, should be included by other scripts as below:
# . ${PROJROOT}/attestation/test/integration/common.sh
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
FILENAME=`basename $0`
# DIRNAME=`dirname $0`
CASENAME=${FILENAME%.*}
# echo ${FILENAME%.*}, ${FILENAME##*.}

TESTDIR_PREFIX=${TESTDIR_PREFIX:-kunpengsecl-test}

RACPKG=${PROJROOT}/attestation/rac/pkg
RAAGENT=${RACPKG}/raagent
RAHUB=${RACPKG}/rahub
# TBPRO=${RACPKG}/tbprovisioner

CMDRAAGENT=${PROJROOT}/attestation/rac/cmd/raagent
CMDRAHUB=${PROJROOT}/attestation/rac/cmd/rahub
RACCONF=${CMDRAAGENT}/config.yaml
RAHUBCONF=${CMDRAHUB}/config.yaml
BIOSFILE=binary_bios_measurements
IMAFILE=ascii_runtime_measurements
TALISTFILE=talist
BIOSMANIFEST=${CMDRAAGENT}/${BIOSFILE}
IMAMANIFEST=${CMDRAAGENT}/${IMAFILE}
TALIST=${CMDRAAGENT}/${TALISTFILE}

RAS=${PROJROOT}/attestation/ras/pkg/ras
RASCONF=${PROJROOT}/attestation/ras/cmd/config.yaml
RASAUTHKEY=${PROJROOT}/attestation/ras/cmd/ecdsakey.pub

TAS=${PROJROOT}/attestation/tas/pkg/akserver
TASCONF=${PROJROOT}/attestation/tas/cmd/config.yaml
CMDTAS=${PROJROOT}/attestation/tas/cmd
TASAUTHKEY=${PROJROOT}/attestation/tas/cmd/ecdsakey.pub

PKGPATH=${PROJROOT}/attestation/tee/demo/pkg
CMDQCASERVER=${PROJROOT}/attestation/tee/demo/qca_demo/cmd
CMDATTESTER=${PROJROOT}/attestation/tee/demo/attester_demo/cmd

QCASERVER=${PKGPATH}/qcaserver
QCACONF=${CMDQCASERVER}/config.yaml
ATTESTER=${PKGPATH}/attester
ATTESTERCONF=${CMDATTESTER}/config.yaml
BASEVALUE=${CMDATTESTER}/basevalue.txt

# EXAMPLE=${PROJROOT}/attestation/ras/example
# SAMPLEAUTHSVR=${EXAMPLE}/pkg/server
# SAMPLECLIENT=${EXAMPLE}/pkg/client
# SAMPLEAUTHSVRAUTHKEY=${EXAMPLE}/sampleauthserver/ecdsakey
# SAMPLEAUTHSVRSTATIC=${EXAMPLE}/sampleauthserver/static
