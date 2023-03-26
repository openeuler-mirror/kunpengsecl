
.PHONY: all build test install clean
all build: 
	export CC=gcc CFLAGS=-fPIC; python3 config64.py -o 32 -o 33

install: all build;

test:
	@echo "to be implemented!"

clean:
	@rm -rf *.o *.so *.a
