PKGPATH = pkg
TESTEES = ./cache ./clientapi ./cmd/ras ./config ./dao ./entity ./pca ./restapi ./trustmgr ./verifier

all: build

test:
	go test $(TESTEES)

build: vendor
	go build -mod=vendor -o $(PKGPATH)/ras cmd/ras/*.go

clean:
	@rm -rf $(PKGPATH)

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./clientapi/api.proto

vendor:
	go mod vendor

oapi-codegen:
	oapi-codegen -package restapi -generate types,server,client restapi/api.yaml > restapi/api.gen.go

.PHONY: all build test clean install check gofmt proto vendor oapi-codegen
