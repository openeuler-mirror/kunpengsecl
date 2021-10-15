
TESTEES=./ractools

all: build

test:
	go test $(TESTEES)

build: 
	go build -mod=vendor -o pkg/raagent cmd/raagent/*.go
	go build -mod=vendor -o pkg/ractools ractools/*.go
	go build -mod=vendor -o pkg/tbprovisioner cmd/tbprovisioner/*.go
	go build -mod=vendor -o pkg/rahub cmd/rahub/*.go

clean:
	@rm -rf pkg

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -e gofmt -e gocyclo -e errorlint -e gosec

gofmt:
	gofmt -s -w *

.PHONY: all build test clean install check
