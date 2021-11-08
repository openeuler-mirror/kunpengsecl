#!/bin/bash
check_results=`rpm -qa | grep "container-selinux"`
echo "command(rpm -qa) results are: $check_results"
if [[ $check_results =~ "container-selinux" ]] 
then 
    echo "package container-selinux has already installed. "
else 
    echo "This is going to install package container-selinux"
    wget http://mirror.centos.org/centos/7/extras/x86_64/Packages/container-selinux-2.119.2-1.911c772.el7_8.noarch.rpm
    rpm -ivh container-selinux-2.119.2-1.911c772.el7_8.noarch.rpm
fi
check_selinux=`getenforce`
if [[ $check_selinux == "enforcing" ]] 
then
    echo "Selinux is enforcing"
else
    echo "Selinux is not enforcing,this is going to enable selinux(enforing)"
    setenforce 1
    echo "finish!"
fi
