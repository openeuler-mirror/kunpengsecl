subdir = ras rac

.PHONY: all build test clean install
all build test clean install:
	for name in $(subdir); do \
		make -C $$name $@;\
	done

