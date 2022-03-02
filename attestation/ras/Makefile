PKGPATH = pkg
TESTEES = ./cache ./clientapi ./cmd/ras ./config ./dao ./entity ./restapi ./trustmgr ./verifier ./pca
RASPATH = ./cmd/ras
SCRPATH = ../quick-scripts
TOPPATH = ../..
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
BINTAR = /usr/bin

all: build

test:
	PWD=$(shell pwd); cd ../quick-scripts; sh ./clear-database.sh; cd $(PWD)
	go test -count=1 $(TESTEES)

build:
	go build -mod=vendor -o $(PKGPATH)/ras cmd/ras/*.go
	go build -mod=vendor -o $(PKGPATH)/pca pca/*.go
	go build -mod=vendor -o $(PKGPATH)/config config/*.go
	go build -mod=vendor -o $(PKGPATH)/trustmgr trustmgr/*.go
	go build -mod=vendor -o $(PKGPATH)/verifier verifier/*.go
	go build -mod=vendor -o $(PKGPATH)/cache cache/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi clientapi/*.go
	go build -mod=vendor -o $(PKGPATH)/dao dao/*.go
	go build -mod=vendor -o $(PKGPATH)/entity entity/*.go
	go build -mod=vendor -o $(PKGPATH)/restapi restapi/*.go
	make -C example $@ || exit $$?

clean:
	@rm -rf $(PKGPATH)
	make -C example $@ || exit $$?

install: build
	sudo mkdir -p $(DESTDIR)$(ETCTAR)/ras $(DESTDIR)$(ETCTAR)/auth_file $(DESTDIR)$(SHARETAR)/ras $(DESTDIR)$(DOCTAR)/ras $(DESTDIR)$(BINTAR)
	sudo install -m 555 $(PKGPATH)/ras $(DESTDIR)$(BINTAR)
	sudo install -m 644 $(RASPATH)/config.yaml $(DESTDIR)$(ETCTAR)/ras
	sudo install -m 644 $(RASPATH)/ecdsakey.pub $(DESTDIR)$(ETCTAR)/auth_file
	sudo install -m 555 $(SCRPATH)/prepare-database-env.sh $(DESTDIR)$(SHARETAR)/ras
	sudo install -m 555 $(SCRPATH)/clear-database.sh $(DESTDIR)$(SHARETAR)/ras
	sudo install -m 555 $(SCRPATH)/createTable.sql $(DESTDIR)$(SHARETAR)/ras
	sudo install -m 555 $(SCRPATH)/dropTable.sql $(DESTDIR)$(SHARETAR)/ras
	sudo install -m 555 $(SCRPATH)/clearTable.sql $(DESTDIR)$(SHARETAR)/ras
	sudo install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/ras
	sudo install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/ras
	sudo install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/ras

uninstall:
ifeq ($(DESTDIR),)
	@sudo rm -rf $(BINTAR)/raagent $(BINTAR)/rahub $(BINTAR)/tbprovisioner $(BINTAR)/ras $(ETCTAR) $(SHARETAR) $(DOCTAR)
else
	@sudo rm -rf $(DESTDIR)
endif

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./clientapi/api.proto

oapi-codegen:
	oapi-codegen -package restapi -generate types,server,client,spec restapi/api.yaml > restapi/api.gen.go

.PHONY: all build test clean install uninstall check gofmt proto oapi-codegen
