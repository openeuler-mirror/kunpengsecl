
subdir = ras rac

.PHONY: all build test clean install check vendor
build: vendor

all build test clean install check:
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done

vendor:
	go mod vendor
