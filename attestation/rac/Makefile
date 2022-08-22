
PKGPATH=pkg
TESTEES=./ractools
RACPATH = ./cmd/raagent
HUBPATH = ./cmd/rahub
SCRPATH = ../quick-scripts/integritytools
TOPPATH = ../..
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
BINTAR = /usr/bin

all: build

test:
	go test -count=1 $(TESTEES)

build: 
	go build -mod=vendor -o $(PKGPATH)/ractools ractools/*.go
	go build -mod=vendor -o $(PKGPATH)/raagent cmd/raagent/*.go
	#go build -mod=vendor -o $(PKGPATH)/tbprovisioner cmd/tbprovisioner/*.go
	go build -mod=vendor -o $(PKGPATH)/rahub cmd/rahub/*.go


clean:
	@rm -rf $(PKGPATH)

install: build
	sudo mkdir -p $(DESTDIR)$(ETCTAR)/rac $(DESTDIR)$(ETCTAR)/rahub $(DESTDIR)$(ETCTAR)/auth_file $(DESTDIR)$(SHARETAR)/rac $(DESTDIR)$(DOCTAR)/rac $(DESTDIR)$(DOCTAR)/rahub $(DESTDIR)$(BINTAR)
	sudo install -m 555 pkg/raagent $(DESTDIR)$(BINTAR)
	sudo install -m 555 pkg/rahub $(DESTDIR)$(BINTAR)
###	sudo install -m 555 pkg/tbprovisioner $(DESTDIR)$(BINTAR)
	sudo install -m 644 $(RACPATH)/config.yaml $(DESTDIR)$(ETCTAR)/rac
	sudo install -m 644 $(HUBPATH)/config.yaml $(DESTDIR)$(ETCTAR)/rahub
	sudo install -m 644 $(RACPATH)/ascii_runtime_measurements $(DESTDIR)$(ETCTAR)/auth_file
	sudo install -m 644 $(RACPATH)/binary_bios_measurements $(DESTDIR)$(ETCTAR)/auth_file
	sudo install -m 555 $(SCRPATH)/*.sh $(DESTDIR)$(SHARETAR)/rac
	sudo install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/rahub
	sudo install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/rahub
	sudo install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/rahub

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
