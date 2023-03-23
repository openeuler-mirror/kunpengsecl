#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
echo "Starting the script..."
QCACONFPATH=${HOME}/.config/attestation/qcaserver
QCACONF=/etc/attestation/qcaserver/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${QCACONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $QCACONF $QCACONFPATH

echo "Initializing the configuration files done."
echo "Script execution complete!"