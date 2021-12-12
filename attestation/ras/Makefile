PKGPATH = pkg
TESTEES = ./cache ./clientapi ./cmd/ras ./config ./dao ./entity ./restapi ./trustmgr ./verifier ./pca

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

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./clientapi/api.proto

oapi-codegen:
	oapi-codegen -package restapi -generate types,server,client,spec restapi/api.yaml > restapi/api.gen.go

.PHONY: all build test clean install check gofmt proto oapi-codegen
