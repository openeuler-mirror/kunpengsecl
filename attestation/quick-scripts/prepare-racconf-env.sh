#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
### Each user is assigned its own configuration files.
echo "Starting the script..."
RACCONFPATH=${HOME}/.config/attestation/rac
RACCONF=/etc/attestation/rac/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${RACCONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $RACCONF $RACCONFPATH

### modify some test files' save and read paths
sed -i "s?ectestfile: \"\"?ecfile: \"${RACCONFPATH}/ec.crt\"?g" ${RACCONFPATH}/config.yaml
sed -i "s?ectestfile: \"\"?ectestfile: \"${RACCONFPATH}/ectest.crt\"?g" ${RACCONFPATH}/config.yaml
sed -i "s?ictestfile: \"\"?icfile: \"${RACCONFPATH}/ic.crt\"?g" ${RACCONFPATH}/config.yaml
sed -i "s?ictestfile: \"\"?ictestfile: \"${RACCONFPATH}/ictest.crt\"?g" ${RACCONFPATH}/config.yaml
echo "Initializing the configuration files done."
echo "Script execution complete!"