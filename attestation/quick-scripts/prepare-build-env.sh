#/bin/sh

sudo dnf install -y make golang
go env -w GOPROXY="https://goproxy.io,direct"
go env -w GO111MODULE="on"
go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.41.1
