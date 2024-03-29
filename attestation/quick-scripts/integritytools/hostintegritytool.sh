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
check_results=`uname -a | grep -i "ubuntu"`
echo "command(uname) result is: $check_results"
  cat>/etc/ima/ima-policy<<EOF
dont_measure fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_measure fsmagic=0x01021994
dont_measure fsmagic=0x858458f6
dont_measure fsmagic=0x73636673
measure func=FILE_MMAP mask=MAY_EXEC 
measure func=BPRM_CHECK
measure func=MODULE_CHECK uid=0
measure func=PATH_CHECK mask=MAY_READ uid=0
EOF

existed_cmdline=`grep -i 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ima ima_template=ima-ng ima_hash=sha256"' /etc/default/grub`
if [ -z "$existed_cmdline" ]
then
  sed -i '$a GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX ima ima_template=ima-ng ima_hash=sha256"' /etc/default/grub
fi

if [ -z "$check_results" ]
then
  path=/etc/selinux/config
  selinux=`sed -rn "/^(SELINUX=).*\$/p" $path`
  sed -ri "s@^(SELINUX=).*\$@\1enforcing@g" $path
  touch /.autorelabel
  cat>>/etc/ima/ima-policy<<EOF
dont_measure obj_type=fsadm_log_t
dont_measure obj_type=rsync_log_t
dont_measure obj_type=wtmp_t
dont_measure obj_type=auth_cache_t
dont_measure obj_type=cron_log_t
dont_measure obj_type=faillog_t
dont_measure obj_type=getty_log_t
dont_measure obj_type=initrc_var_log_t
dont_measure obj_type=lastlog_t
dont_measure obj_type=nscd_log_t
dont_measure obj_type=var_log_t
EOF
grub2-mkconfig -o /boot/efi/EFI/openEuler/grub.cfg
else
  update-grub
fi
read -p "The ima policy has been written in the file,please restart your device now[y/n] " input
case $input in
        [yY]*)
                reboot
                ;;
        [nN]*)
                exit
                ;;
        *)
                echo "Just enter y or n, please."
                exit
                ;;
esac
