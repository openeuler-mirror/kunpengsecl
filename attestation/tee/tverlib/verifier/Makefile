build:teeverifier.c teeverifier.h common.h
	gcc -fPIC -shared -o libteeverifier.so teeverifier.c -I /usr/local/include -L /usr/local/lib -lcrypto

test:teeverify_test.c teeverifier.c
	gcc teeverify_test.c -o test.out -I /usr/local/include -L /usr/local/lib -lcrypto

clean:
	@rm -rf *.o *.so *.out
