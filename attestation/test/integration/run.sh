#!/bin/bash
# this scripts should be run under the root folder of kunpengsecl project
#set -eux
PROJROOT=.
INTEGRATIONDIR=${PROJROOT}/attestation/test/integration
LOG=${PROJROOT}/itest.log

run () {
    if  [ -s "${INTEGRATIONDIR}/$1.sh" ]
    then
        bash "${INTEGRATIONDIR}/$1.sh" >> ${LOG} 2>/dev/null
        echo -n "test $1: "
        if (($? == 0))
        then
            echo -e "\tpass"
        else
            echo -e "\tfail"
        fi
    else
        echo "specified test $1 doesn't exist"
    fi
}

echo "Please check log ${LOG} for more test details"
echo "Running tests ..."

# run the specified test if $1 is given
if (($# == 1))
then
    run $1
    exit
fi

# run all existing tests in the test folder
ALLFILES=$(ls ${INTEGRATIONDIR})
for FILE in ${ALLFILES}
do
    if [ "${FILE%%[0-9].[0-9]*.sh}" == "" ]
    then
        run ${FILE%.sh}
    fi
done