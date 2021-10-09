
TESTEES=./raagent ./ractools ./rahub ./tbprovisioner

all: build

test:
	go test $(TESTEES)

build: vendor
	go build -mod=vendor -o pkg/raagent raagent/*.go
	go build -mod=vendor -o pkg/ractools ractools/*.go
	go build -mod=vendor -o pkg/tbprovisioner tbprovisioner/*.go
	go build -mod=vendor -o pkg/rahub rahub/*.go

clean:
	@rm -rf pkg

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -e gofmt -e gocyclo -e errorlint -e gosec

vendor:
	go mod vendor

.PHONY: all build test clean install check vendor
