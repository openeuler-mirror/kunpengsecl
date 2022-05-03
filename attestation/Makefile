
subdir = ras rac tee

.PHONY: all build test clean install check
build: vendor

all build test clean install check:
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done

vendor:
	go mod vendor && cp -r $$(go env GOPATH)/pkg/mod/github.com/google/go-tpm-tools\@v0.2.1/simulator/ms-tpm-20-ref/ vendor/github.com/google/go-tpm-tools/simulator/ && chmod -R a+w vendor/github.com/google/go-tpm-tools/simulator
