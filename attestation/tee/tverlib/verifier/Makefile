main:verifier.c verifier.h
	gcc -o test.o verifier.c -I /usr/local/include -L /usr/local/lib -lcrypto
shell:test.o
	./test.o
clean:
	rm -rf *.o

