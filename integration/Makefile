PKGPATH = pkg
TESTEES = ./sampleauthserver ./sampleclient

all: build

test:
	go test -count=1 $(TESTEES)

build:
	go build -mod=vendor -o $(PKGPATH)/server ./sampleauthserver/*.go
	go build -mod=vendor -o $(PKGPATH)/client ./sampleclient/*.go

clean:
	@rm -rf $(PKGPATH)

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

vendor:
	go mod vendor

.PHONY: all build test clean install check gofmt
