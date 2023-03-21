#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
echo "Starting the script..."
ATTESTERCONFPATH=${HOME}/.config/attestation/attester
ATTESTERCONF=/etc/attestation/attester/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${ATTESTERCONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $ATTESTERCONF $ATTESTERCONFPATH

echo "Initializing the configuration files done."
echo "Script execution complete!"