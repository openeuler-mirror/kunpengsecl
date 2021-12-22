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
