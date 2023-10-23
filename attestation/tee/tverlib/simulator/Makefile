ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation

.PHONY: all build test clean install
all build: build-libqca build-libteec

build-libqca: teeqca.c teeqca.h
	gcc -fPIC -shared -o libqca.so teeqca.c -lcjson -I../../../rac/ka/teesimulator

build-libteec: teec.c
	gcc -fPIC -shared -o libteec.so teec.c

install: all build
	mkdir -p $(DESTDIR)$(ETCTAR)/qcaserver $(DESTDIR)$(SHARETAR)/qcaserver $(DESTDIR)$(DOCTAR)/qcaserver $(DESTDIR)$(BINTAR)
	install -m 755 libqca.so $(DESTDIR)$(SHARETAR)/qcaserver
	install -m 755 libteec.so $(DESTDIR)$(SHARETAR)/qcaserver

test: 

clean:
	@rm -rf *.o *.so *.out
