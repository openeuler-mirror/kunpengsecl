
.PHONY: all build test clean
all build: teeverifier.c teeverifier.h common.h
	gcc -fPIC -shared -o libteeverifier.so teeverifier.c ../miracl/core.a -I /usr/local/include -I ../miracl -L /usr/local/lib -lcrypto

test: teeverify_test.c teeverifier.c
	gcc teeverify_test.c ../miracl/core.a -o test.out -I /usr/local/include -I ../miracl -L /usr/local/lib -lcrypto

clean:
	@rm -rf *.o *.so *.out
