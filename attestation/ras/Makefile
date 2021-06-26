
all: build

test:
	@echo "to be completed"

build:
	go build -mod=vendor -o pkg/ras cmd/ras/*.go

clean:
	@rm -rf pkg

install:
	@echo "to be completed"

check:
	$(shell go env GOPATH)/bin/golangci-lint run -E gofmt -E gocyclo -E errorlint -E gosec

.PHONY: all build test clean install check
