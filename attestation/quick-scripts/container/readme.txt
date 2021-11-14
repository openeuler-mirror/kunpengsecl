This file is about how to use the scripts(selinux-test.sh and ima-policy.sh)
If you want to use container measurement function，you need to use a script(selinux-test.sh) to test the status of selinux.
The status of selinux is on is a prerequisite for opening the container measurement, because we need to use some tags of selinux, this script will check whether the package is installed, if it is not installed, download and install it. When you see success, the step is executed complete.
After checking the status of selinux, we need to run ima-policy.sh to write the policy into ima. The policies include container policies and non-container policies.In this script, you need to confirm whether you need to restart the system. The selinux status and measurement rules will take effect after the system is restarted. You can also choose not to restart temporarily and restart the system yourself later.
In short, we need to run selinux-test.sh first, and then run ima-policy.sh.
