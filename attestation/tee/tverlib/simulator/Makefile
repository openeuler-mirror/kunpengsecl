
.PHONY: all build test clean
all build: build-libqca build-libteec

build-libqca: teeqca.c teeqca.h
	gcc -fPIC -shared -o libqca.so teeqca.c

build-libteec: teec.c
	gcc -fPIC -shared -o libteec.so teec.c

test: 

clean:
	@rm -rf *.o *.so *.out
