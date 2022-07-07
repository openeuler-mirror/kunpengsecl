PKGPATH = pkg
TESTEES = ./attester_demo/cmd ./attester_demo/attestertools ./qca_demo/cmd ./qca_demo/qapi ./qca_demo/qcatools
ATTESTERPATH = ./attester_demo/cmd
ATOOLSPATH = ./attester_demo/attestertools
QCAPATH = ./qca_demo/cmd
QAPIPATH = ./qca_demo/qapi
QTOOLSPATH = ./qca_demo/qcatools


all: build

build:
	go build -mod=vendor -o $(PKGPATH)/attester $(ATTESTERPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/atools $(ATOOLSPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qcaserver $(QCAPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qapi $(QAPIPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qtools $(QTOOLSPATH)/*.go

test:
	go test -count=1 $(TESTEES)

clean:
	@rm -rf $(PKGPATH)

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./qca_demo/qapi/api.proto
