build:teeverifier.c teeverifier.h common.h
	gcc -fPIC -shared -o libteeverifier.so teeverifier.c -I /usr/local/include -L /usr/local/lib -lcrypto

test:verify_test.c teeverifier.c
	gcc verify_test.c -o test.out -I /usr/local/include -L /usr/local/lib -lcrypto
	gcc verifysig_test.c -g -o testsig.out -I /usr/local/include -L /usr/local/lib -lcrypto

clean:
	@rm -rf *.o *.so *.out
