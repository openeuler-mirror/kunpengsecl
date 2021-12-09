#!/bin/bash
check_results=`rpm -qa | grep "container-selinux"`
echo "command(rpm -qa) results are: $check_results"
if [[ $check_results =~ "container-selinux" ]] 
then 
    echo "package container-selinux has already installed."
else 
    echo "This is going to install package container-selinux"
    yum install container-selinux -y
fi
sed -i '$a dont_measure obj_type=container_log_t' /etc/ima/ima-policy
sed -i '$a measure obj_type=container_var_lib_t mask=MAY_EXEC' /etc/ima/ima-policy
sed -i '$a measure obj_type=container_runtime_exec_t mask=MAY_EXEC' /etc/ima/ima-policy
sed -i '$a measure obj_type=container_share_t mask=MAY_EXEC' /etc/ima/ima-policy
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
