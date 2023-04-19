PKGPATH = ./pkg
TA_DIR  = ./cmd/TA
CA_LIB  = ./cmd/CA/libteememca

all: build-c build-go
	cp -rf $(TA_DIR)/*.sec $(PKGPATH)
	cp -rf $(CA_LIB)/*.so $(PKGPATH)

build-c:
	make -C $(TA_DIR)
	make -C $(CA_LIB)

build-go: build-c
	go build -mod=mod -o $(PKGPATH)/tee-device-plugin cmd/CA/plugin/*.go

clean:
	make -C $(TA_DIR) clean
	make -C $(CA_LIB) clean
	rm -rf $(PKGPATH)
