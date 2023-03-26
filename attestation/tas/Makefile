PKGPATH=pkg
TOPPATH = ../..
TASPATH = ./cmd
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
SCRPATH = ../quick-scripts
BINTAR = /usr/bin
TASTEST=./akissuer ./clientapi ./config

all: build

build:
	go build -mod=vendor -o $(PKGPATH)/akserver cmd/*.go
	go build -mod=vendor -o $(PKGPATH)/akissuer akissuer/*.go
	go build -mod=vendor -o $(PKGPATH)/clientapi clientapi/*.go
	go build -mod=vendor -o $(PKGPATH)/config config/*.go
	go build -mod=vendor -o $(PKGPATH)/database database/*.go
	go build -mod=vendor -o $(PKGPATH)/restapi restapi/*.go

install: build
	mkdir -p $(DESTDIR)$(ETCTAR)/tas $(DESTDIR)$(SHARETAR)/tas $(DESTDIR)$(DOCTAR)/tas $(DESTDIR)$(BINTAR)
	install -m 555 $(PKGPATH)/akserver $(DESTDIR)$(BINTAR)/tas
	install -m 644 $(TASPATH)/config.yaml $(DESTDIR)$(ETCTAR)/tas
	install -m 555 $(SCRPATH)/prepare-tasconf-env.sh $(DESTDIR)$(SHARETAR)/tas
	install -m 644 $(TASPATH)/*.pem $(DESTDIR)$(BINTAR)
	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/tas
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/tas
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/tas

test:
	go test -count=1 $(TASTEST)

clean:
	@rm -rf $(PKGPATH)

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./clientapi/api.proto