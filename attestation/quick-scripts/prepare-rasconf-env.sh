#/bin/sh
### This script is used to prepare the configuration files needed for program execution.
### Each user is assigned its own configuration files.
echo "Starting the script..."
RASCONFPATH=${HOME}/.config/attestation/ras
RASCONF=/etc/attestation/ras/config.yaml

### create file directory structure
echo "Initializing directory structure..."
mkdir -p -m 755 ${RASCONFPATH}
echo "Initializing directory structure done."

### copy the initial configuration files to the specific paths
echo "Initializing the configuration files..."
cp $RASCONF $RASCONFPATH

### modify some test files' save and read paths
sed -i "s?pcakeycertfile: \"\"?pcakeycertfile: \"${RASCONFPATH}/pca-ek.crt\"?g" ${RASCONFPATH}/config.yaml
sed -i "s?pcaprivkeyfile: \"\"?pcaprivkeyfile: \"${RASCONFPATH}/pca-ek.key\"?g" ${RASCONFPATH}/config.yaml
sed -i "s?rootkeycertfile: \"\"?rootkeycertfile: \"${RASCONFPATH}/pca-root.crt\"?g" ${RASCONFPATH}/config.yaml
sed -i "s?rootprivkeyfile: \"\"?rootprivkeyfile: \"${RASCONFPATH}/pca-root.key\"?g" ${RASCONFPATH}/config.yaml
sed -i "s?httpskeycertfile: \"\"?httpskeycertfile: \"${RASCONFPATH}/https.crt\"?g" ${RASCONFPATH}/config.yaml
sed -i "s?httpsprivkeyfile: \"\"?httpsprivkeyfile: \"${RASCONFPATH}/https.key\"?g" ${RASCONFPATH}/config.yaml
echo "Initializing the configuration files done."
echo "Script execution complete!"