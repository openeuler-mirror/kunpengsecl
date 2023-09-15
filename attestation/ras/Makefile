
PKGPATH=pkg
TOPPATH = ../..
RASPATH = ./cmd
SCRPATH = ../quick-scripts
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
BINTAR = /usr/bin
TESTEES= ./cache ./clientapi ./config ./trustmgr ./restapi/rim ./kcms/kcmstools ./kcms/kdb ./clientapi/client ./clientapi/server

all: build

test:
	PWD=$(shell pwd); cd ../quick-scripts; sh ./clear-database.sh; cd $(PWD)
	go test -count=1 -p 1 $(TESTEES)

build:
	go build -mod=vendor -o $(PKGPATH)/cache cache/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi/clientapi clientapi/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi/client clientapi/client/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi/server clientapi/server/*.go
	go build -mod=vendor -o $(PKGPATH)/config config/*.go
	go build -mod=vendor -o $(PKGPATH)/trustmgr trustmgr/*.go
	go build -mod=vendor -o $(PKGPATH)/kcms/kcmstools kcms/kcmstools/*.go
	go build -mod=vendor -o $(PKGPATH)/kcms/kdb kcms/kdb/*.go
	go build -mod=vendor -o $(PKGPATH)/ras cmd/*.go
#	make -C example $@ || exit $$?

clean:
	@rm -rf $(PKGPATH)
#	make -C example $@ || exit $$?

install: build
	mkdir -p $(DESTDIR)$(ETCTAR)/ras $(DESTDIR)$(SHARETAR)/ras $(DESTDIR)$(DOCTAR)/ras $(DESTDIR)$(BINTAR)
	install -m 755 $(PKGPATH)/ras $(DESTDIR)$(BINTAR)
	install -m 644 $(RASPATH)/config.yaml $(DESTDIR)$(ETCTAR)/ras
	install -m 755 $(SCRPATH)/prepare-database-env.sh $(DESTDIR)$(SHARETAR)/ras
	install -m 755 $(SCRPATH)/clear-database.sh $(DESTDIR)$(SHARETAR)/ras
	install -m 755 $(SCRPATH)/createTable.sql $(DESTDIR)$(SHARETAR)/ras
	install -m 755 $(SCRPATH)/dropTable.sql $(DESTDIR)$(SHARETAR)/ras
	install -m 755 $(SCRPATH)/clearTable.sql $(DESTDIR)$(SHARETAR)/ras
	install -m 755 $(SCRPATH)/prepare-rasconf-env.sh $(DESTDIR)$(SHARETAR)/ras
	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/ras
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/ras
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/ras

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

restapi:
	$(shell go env GOPATH)/bin/oapi-codegen -package restapi -generate types,server,client,spec -o restapi/api.gen.go restapi/api.yaml

.PHONY: all test build clean install check gofmt proto restapi
