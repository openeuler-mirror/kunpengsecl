
subdir=attestation
delfile=pca-root.crt pca-root.key pca-ek.crt pca-ek.key https.crt https.key ikpri.key ikpub.key ic.crt ectest.crt ectest.key ikpritest.key ikpubtest.key ictest.crt rac-log.txt ras-log.txt rahub-log.txt nodaa-ac.crt daa-ac.crt

.PHONY: all build test clean install check vendor ci-check bat prepare sim-test sim-clean rpm rpm-clean
all build test install check: vendor
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done

vendor:
	make -C attestation vendor || exit $$?;

clean:
	for name in $(delfile); do\
		find . -name $$name -exec rm -f {} \; ;\
	done
	rm -rf  attestation/vendor
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done

test: build

bat: test

prepare:
	for name in $(subdir); do\
		cd $$name; sh quick-scripts/prepare-build-env.sh;\
		cd quick-scripts; sh prepare-database-env.sh;\
		cd ../..;\
	done

ci-check: prepare bat

# run one ras and some racs to do the simulation test.
sim-test: build
	/bin/bash ./attestation/test/sim-test.sh

sim-clean: clean
	-@pkill -u ${USER} ras || true
	-@pkill -u ${USER} raagent || true
	-@pkill -u ${USER} rahub || true
	-@pkill -u ${USER} server || true
	-@pkill -u ${USER} client || true

rpm:
	/bin/bash ./attestation/quick-scripts/buildrpm.sh

rpm-clean:
	rm -rf ./rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SRPMS}

deb: build
	/bin/bash ./attestation/quick-scripts/builddeb.sh

deb-clean: clean
	rm -rf ./debbuild