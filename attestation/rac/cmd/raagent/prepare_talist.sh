#!/bin/bash
#set -eux
### This script is used to prepare the information of ta needed by attestation.
TAHASHPATH="/root/vendor/bin"
TAHASHFILE="./talist"
### if file is exist, remove old ta information in list
if [ -f "$TAHASHFILE" ];then
    echo "file talist already exists..."
    for filename in $TAHASHPATH/*;do
        if [[ ${filename##*/} == hash* ]]
        then
            ta_uuid="${filename:22:36}"
            sed -i '/'"${ta_uuid}"'/d' $TAHASHFILE
        fi
    done
else
    echo "file talist doesn't exist, creating file..."
    touch talist
fi
### add new ta information to list
echo "adding ta information to talist..."
for filename in $TAHASHPATH/*;do
    if [[ ${filename##*/} == hash* ]]
    then
        ta_uuid="${filename:22:36}"
        mem_hash=$(cat ${filename} | grep -A 0 mem_hash | awk '{print $3}')
        img_hash=$(cat ${filename} | grep -A 0 img_hash | awk '{print $3}')
        ta_newinfo=$ta_uuid" false "$mem_hash" "$img_hash
        echo $ta_newinfo >> $TAHASHFILE
    fi
done
