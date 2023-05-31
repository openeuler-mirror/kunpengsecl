#!/bin/bash
set -eux

function check_teecd()
{
    local teecd_sock="/var/itrustee/teecd/teecd.sock"
    if [ ! -e ${teecd_sock} ]; then
        echo "${teecd_sock} is not exist, the host teecd not started"
        return 1
    fi
    return 0
}

function main()
{
    check_teecd
    /vendor/bin/tee-device-plugin -precision 512 -internal 60
}

main