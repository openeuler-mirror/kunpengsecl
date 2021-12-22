#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
INTEGRATIONDIR=${PROJROOT}/attestation/test/integration
. ${INTEGRATIONDIR}/common-def.sh

#rm -rf /tmp/${TESTDIR_PREFIX:-kunpengsecl-test}-??????
rm -rf /tmp/${TESTDIR_PREFIX}-??????
