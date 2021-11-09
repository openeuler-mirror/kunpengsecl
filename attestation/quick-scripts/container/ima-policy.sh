#!/bin/bash
policyPath="/etc/ima"
policyFile="/etc/ima/ima-policy"
if [ ! -d $policyPath ];then
   mkdir -p /etc/ima
   echo "file-path has been made-----------success"
else
   echo "file-path is existed--------------success"
fi
if [ ! -f $policyFile ];then
   touch $policyFile
   echo "file has been made----------------success"
else
   echo "file is existed-------------------success"
fi
cat>/etc/ima/ima-policy<<EOF
dont_measure fsmagic=0x9fa0
dont_appraise fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_appraise fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_appraise fsmagic=0x64626720
dont_measure fsmagic=0x01021994
dont_appraise fsmagic=0x01021994
dont_measure fsmagic=0x858458f6
dont_appraise fsmagic=0x858458f6
dont_measure fsmagic=0x73636673
dont_appraise fsmagic=0x73636673
measure func=FILE_MMAP mask=MAY_EXEC 
measure func=BPRM_CHECK               
dont_measure obj_type=var_log_t
dont_measure obj_type=auditd_log_t
dont_measure obj_type=container_log_t
measure obj_type=container_var_lib_t mask=MAY_EXEC
measure obj_type=container_runtime_exec_t mask=MAY_EXEC
measure func=PATH_CHECK mask=MAY_READ uid=0
EOF
echo "the ima policy has been written in the file,please restart your device"
