build-libqca:teeqca.c teeqca.h
	gcc -fPIC -shared -o libqca.so teeqca.c
build-libteec:teec.c
	gcc -fPIC -shared -o libteec.so teec.c

build: build-libqca build-libteec

test:

clean:
	@rm -rf ./*.so