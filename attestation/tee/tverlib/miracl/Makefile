
.PHONY: all build test install clean
all build: 
	CC=gcc CFLAGS=-fPIC python3 config64.py -o 33 > ./build.log

install: all build

test:
	@echo "to be implemented!"

clean:
	@rm -rf *.o *.so *.a build.log
