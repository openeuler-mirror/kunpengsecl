###This file is about how to use the tools.
###If you want to use host measurement function，you need to use a script(hostintegritytool.sh) to enable it.
###This script writes the ima-policy for measuring the integrity of the host into the file, and sets the ima hash to sha-256. Because the kernel command line is used, it needs to be restarted before it takes effect. If you also need to open the container measurement or PCIe measurement, you can restart the host after executing all integrity tools.
/bin/bash hostintegritytool.sh

###If you want to use container measurement function，you need to use a script(containerintegritytool.sh) to enable it.And before it,you need to execute hostintegritytool.sh first.
###This script installs the packages required by the measurement container on the host. Before executing this script, please ensure that the host integrity tool script has been executed.
/bin/bash containerintegritytool.sh

###If you want to use pcie measurement function，you need to use a script(pcieintegritytool.sh) to enable it.And before it,you need to execute hostintegritytool.sh first.
###This script writes the ima policy required to measure PCIe into the corresponding file. Before executing this script, please ensure that the host integrity tool script has been executed.
/bin/bash pcieintegritytool.sh