
all: build

test:
	@echo "to be completed"

build:
	go build -mod=vendor -o pkg/raagent raagent/*.go
	go build -mod=vendor -o pkg/ractools ractools/*.go
	go build -mod=vendor -o pkg/tbprovisioner tbprovisioner/*.go
	go build -mod=vendor -o pkg/rahub rahub/*.go

clean:
	@rm -rf pkg

install:
	@echo "to be completed"

.PHONY: all build test clean install
