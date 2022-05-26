build:verifier.c verifier.h common.h
	gcc -c -fPIC verifier.c -I /usr/local/include -L /usr/local/lib -lcrypto
	gcc -shared -fPIC -o libverifier.so verifier.o

test:verify_test.c verifier.c
	gcc verify_test.c -o test.out -I /usr/local/include -L /usr/local/lib -lcrypto
	gcc verifysig_test.c -g -o testsig.out -I /usr/local/include -L /usr/local/lib -lcrypto

clean:
	@rm -rf *.o *.so *.out
