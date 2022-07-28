#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
### Each user is assigned its own configuration files.
### You should run this script under the root folder of kunpengsecl project, otherwise it will be wrong!!!
echo "Starting the script..."
HUBCONFPATH=${HOME}/.config/attestation/rahub
HUBCONF=/etc/attestation/rahub/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${HUBCONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $HUBCONF $HUBCONFPATH
echo "Initializing the configuration files done."
echo "Script execution complete!"