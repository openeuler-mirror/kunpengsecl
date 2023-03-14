
PKGPATH=pkg
TESTEES= .

all: build

test:
	go test -count=1 $(TESTEES)

build:
	go build -mod=vendor -o $(PKGPATH) *.go

clean:
	@rm -rf $(PKGPATH)

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

gofmt:
	gofmt -s -w *

.PHONY: all test build clean install check gofmt