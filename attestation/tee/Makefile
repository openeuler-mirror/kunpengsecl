subdir = ./tverlib/miracl ./tverlib/verifier ./tverlib/simulator demo

.PHONY: all build test clean install check

all build test clean install check:
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done
