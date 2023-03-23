#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
### Each user is assigned its own configuration files.
echo "Starting the script..."
TASCONFPATH=${HOME}/.config/attestation/tas
TASCONF=/etc/attestation/tas/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${TASCONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $TASCONF $TASCONFPATH

### generate AKS private key and AKS cert
echo "Generating AKS key and cert..."
openssl genrsa -out ${TASCONFPATH}/aspriv.key 4096
openssl req -new -x509 -days 365 -key ${TASCONFPATH}/aspriv.key -out ${TASCONFPATH}/ascert.crt

echo "Initializing the configuration files done."
echo "Script execution complete!"