#/bin/sh

sudo dnf install -y make golang
go env -w GOPROXY="https://goproxy.cn,direct"
go env -w GO111MODULE="on"
go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.41.1

sudo dnf install -y protobuf-compiler
protoc --version
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
go get google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
export PATH="$PATH:$(go env GOPATH)/bin"

go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.8.1
sudo dnf install -y openssl-devel
go get github.com/google/go-tpm-tools/simulator@v0.2.1
