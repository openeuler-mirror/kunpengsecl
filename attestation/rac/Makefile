
PKGPATH=pkg
TESTEES=./ractools ./ka/katools
RACPATH = ./cmd/raagent
KTALIBPATH = ka/ktalib
HUBPATH = ./cmd/rahub
SCRPATH = ../quick-scripts
TOPPATH = ../..
LIBTAR = /usr/lib64
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
BINTAR = /usr/bin
PROCESSOR = $(shell uname -p)

all: build

test:
	go test -count=1 $(TESTEES)

build: build-libkta
	go build -mod=vendor -o $(PKGPATH)/ractools ractools/*.go
	go build -mod=vendor -o $(PKGPATH)/raagent cmd/raagent/*.go
	#go build -mod=vendor -o $(PKGPATH)/tbprovisioner cmd/tbprovisioner/*.go
	go build -mod=vendor -o $(PKGPATH)/rahub cmd/rahub/*.go

build-libkta:
ifeq ($(PROCESSOR), aarch64)
	cd $(KTALIBPATH); \
	gcc -fPIC -shared -o libkta.so ktalib.c -I /opt/itrustee_sdk/include/CA/
endif

clean:
	@rm -rf $(PKGPATH)
ifeq ($(PROCESSOR), aarch64)
	@rm -rf $(KTALIBPATH)/libkta.so
endif

install: build
	mkdir -p $(DESTDIR)$(ETCTAR)/rac $(DESTDIR)$(ETCTAR)/rahub $(DESTDIR)$(ETCTAR)/default_test $(DESTDIR)$(SHARETAR)/rac $(DESTDIR)$(SHARETAR)/rahub $(DESTDIR)$(DOCTAR)/rac $(DESTDIR)$(DOCTAR)/rahub $(DESTDIR)$(BINTAR)
	install -m 555 pkg/raagent $(DESTDIR)$(BINTAR)
	install -m 555 pkg/rahub $(DESTDIR)$(BINTAR)
###	install -m 555 pkg/tbprovisioner $(DESTDIR)$(BINTAR)
	install -m 644 $(RACPATH)/config.yaml $(DESTDIR)$(ETCTAR)/rac
	install -m 644 $(HUBPATH)/config.yaml $(DESTDIR)$(ETCTAR)/rahub
	install -m 644 $(RACPATH)/ascii_runtime_measurements* $(DESTDIR)$(ETCTAR)/default_test
	install -m 644 $(RACPATH)/binary_bios_measurements* $(DESTDIR)$(ETCTAR)/default_test
	install -m 555 $(SCRPATH)/integritytools/*.sh $(DESTDIR)$(SHARETAR)/rac
	install -m 555 $(SCRPATH)/prepare-racconf-env.sh $(DESTDIR)$(SHARETAR)/rac/
	install -m 555 $(SCRPATH)/prepare-hubconf-env.sh $(DESTDIR)$(SHARETAR)/rahub/

	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/rac
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/rac
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/rac
	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/rahub
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/rahub
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/rahub
ifeq ($(PROCESSOR), aarch64)
	install -m 555 $(KTALIBPATH)/libkta.so $(DESTDIR)$(LIBTAR)/
endif

uninstall:
ifeq ($(DESTDIR),)
	@sudo rm -rf $(BINTAR)/raagent $(BINTAR)/rahub $(BINTAR)/tbprovisioner $(BINTAR)/ras $(ETCTAR) $(SHARETAR) $(DOCTAR)
else
	@sudo rm -rf $(DESTDIR)
endif

check:
	$(shell go env GOPATH)/bin/golangci-lint run -e gofmt -e gocyclo -e errorlint -e gosec

gofmt:
	gofmt -s -w *

.PHONY: all test build clean install check gofmt
