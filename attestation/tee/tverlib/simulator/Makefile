
.PHONY: all build test clean install
all build: build-libqca build-libteec

build-libqca: teeqca.c teeqca.h
	gcc -fPIC -shared -o libqca.so teeqca.c

build-libteec: teec.c
	gcc -fPIC -shared -o libteec.so teec.c

install: ;

test: 

clean:
	@rm -rf *.o *.so *.out
