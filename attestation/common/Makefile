
PKGPATH=pkg
TESTEES=./cryptotools ./logger ./typdefs ./verifier

all: build

test:
	go test -count=1 $(TESTEES)

build:
	go build -mod=vendor -o $(PKGPATH)/typdefs typdefs/*.go
	go build -mod=vendor -o $(PKGPATH)/logger logger/*.go
	go build -mod=vendor -o $(PKGPATH)/cryptotools cryptotools/*.go

clean:
	@rm -rf $(PKGPATH)

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

.PHONY: all test build clean install check gofmt
