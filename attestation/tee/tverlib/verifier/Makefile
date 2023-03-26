LIBTAR = /usr/lib64

.PHONY: all build test clean install
all build: teeverifier.c teeverifier.h common.h
	gcc -fPIC -shared -o libteeverifier.so teeverifier.c ../miracl/core.a -I /usr/local/include -I ../miracl -L /usr/local/lib -lcrypto

install:
	mkdir -p $(DESTDIR)$(LIBTAR)
	install -m 555 libteeverifier.so $(DESTDIR)$(LIBTAR)

test: teeverify_test.c teeverifier.c
	gcc teeverify_test.c ../miracl/core.a -o test.out -I /usr/local/include -I ../miracl -L /usr/local/lib -lcrypto

clean:
	@rm -rf *.o *.so *.out
