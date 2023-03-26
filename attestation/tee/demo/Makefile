PKGPATH = pkg
TOPPATH = ../../..
TESTEES = ./attester_demo/cmd ./attester_demo/attestertools ./qca_demo/cmd ./qca_demo/qapi ./qca_demo/qcatools
ATTESTERPATH = ./attester_demo/cmd
ATOOLSPATH = ./attester_demo/attestertools
QCAPATH = ./qca_demo/cmd
QAPIPATH = ./qca_demo/qapi
QTOOLSPATH = ./qca_demo/qcatools
ETCTAR = /etc/attestation
SHARETAR = /usr/share/attestation
DOCTAR = /usr/share/doc/attestation
BINTAR = /usr/bin
SCRPATH = ../../quick-scripts
VERIFIERSOPATH = ../tverlib/verifier
QCASOPATH = ../tverlib/simulator

all: build

build:
	go build -mod=vendor -o $(PKGPATH)/attester $(ATTESTERPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/atools $(ATOOLSPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qcaserver $(QCAPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qapi $(QAPIPATH)/*.go
	go build -mod=vendor -o $(PKGPATH)/qtools $(QTOOLSPATH)/*.go

install: build
	mkdir -p $(DESTDIR)$(ETCTAR)/attester $(DESTDIR)$(SHARETAR)/attester $(DESTDIR)$(DOCTAR)/attester $(DESTDIR)$(BINTAR)
	mkdir -p $(DESTDIR)$(ETCTAR)/qcaserver $(DESTDIR)$(SHARETAR)/qcaserver $(DESTDIR)$(DOCTAR)/qcaserver $(DESTDIR)$(BINTAR)
	install -m 555 $(PKGPATH)/attester $(DESTDIR)$(BINTAR)
	install -m 644 $(ATTESTERPATH)/config.yaml $(DESTDIR)$(ETCTAR)/attester
	install -m 555 $(SCRPATH)/prepare-attesterconf-env.sh $(DESTDIR)$(SHARETAR)/attester
	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/attester
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/attester
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/attester
	install -m 555 $(PKGPATH)/qcaserver $(DESTDIR)$(BINTAR)
	install -m 644 $(QCAPATH)/config.yaml $(DESTDIR)$(ETCTAR)/qcaserver
	install -m 555 $(SCRPATH)/prepare-qcaconf-env.sh $(DESTDIR)$(SHARETAR)/qcaserver
	install -m 644 $(TOPPATH)/README.md $(DESTDIR)$(DOCTAR)/qcaserver
	install -m 644 $(TOPPATH)/README.en.md $(DESTDIR)$(DOCTAR)/qcaserver
	install -m 644 $(TOPPATH)/LICENSE $(DESTDIR)$(DOCTAR)/qcaserver

test:
	go test -count=1 $(TESTEES)

clean:
	@rm -rf $(PKGPATH)

proto:
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative ./qca_demo/qapi/api.proto
