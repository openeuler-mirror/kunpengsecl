all : build
PKGPATH=pkg
TASTEST=./akissuer ./clientapi ./config

build:
	go build -mod=vendor -o $(PKGPATH)/akissuer akissuer/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi clientapi/*.go
	go build -mod=vendor -o $(PKGPATH)/config config/*.go
	go build -mod=vendor -o $(PKGPATH)/database database/*.go
	go build -mod=vendor -o $(PKGPATH)/restapi restapi/*.go

test:
	go test -count=1 $(TASTEST)

clean:
	@rm -rf $(PKGPATH)

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./clientapi/api.proto