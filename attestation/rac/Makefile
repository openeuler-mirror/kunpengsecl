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
	go build -mod=vendor -o pkg/raagent cmd/raagent/*.go
	go build -mod=vendor -o pkg/ractools ractools/*.go
	go build -mod=vendor -o pkg/tbprovisioner cmd/tbprovisioner/*.go
	go build -mod=vendor -o pkg/rahub cmd/rahub/*.go

clean:
	@rm -rf pkg

install: build
	sudo mkdir -p $(ETCTAR)/rac $(ETCTAR)/rahub $(ETCTAR)/auth_file $(SHARETAR)/rac $(DOCTAR)/rac $(DOCTAR)/rahub
	sudo install -m 555 pkg/raagent $(BINTAR)
	sudo install -m 555 pkg/rahub $(BINTAR)
	sudo install -m 555 pkg/tbprovisioner $(BINTAR)
	sudo install -m 644 $(RACPATH)/config.yaml $(ETCTAR)/rac
	sudo install -m 644 $(HUBPATH)/config.yaml $(ETCTAR)/rahub
	sudo install -m 644 $(RACPATH)/ascii_runtime_measurements $(ETCTAR)/auth_file
	sudo install -m 644 $(RACPATH)/binary_bios_measurements $(ETCTAR)/auth_file
	sudo install -m 555 $(SCRPATH)/*.sh $(SHARETAR)/rac
	sudo install -m 644 $(TOPPATH)/README.md $(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/README.en.md $(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/LICENSE $(DOCTAR)/rac
	sudo install -m 644 $(TOPPATH)/README.md $(DOCTAR)/rahub
	sudo install -m 644 $(TOPPATH)/README.en.md $(DOCTAR)/rahub
	sudo install -m 644 $(TOPPATH)/LICENSE $(DOCTAR)/rahub

uninstall:
	@sudo rm -rf $(BINTAR)/raagent $(BINTAR)/rahub $(BINTAR)/tbprovisioner $(BINTAR)/ras $(ETCTAR) $(SHARETAR) $(DOCTAR)

check:
	$(shell go env GOPATH)/bin/golangci-lint run -e gofmt -e gocyclo -e errorlint -e gosec

gofmt:
	gofmt -s -w *

.PHONY: all build test clean install uninstall check
