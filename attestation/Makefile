
subdir=common tee ras rac tas kms

.PHONY: all build test clean install check
all build test install check: vendor

all build test clean install check:
	for name in $(subdir); do\
		make -C $$name $@ || exit $$?;\
	done

vendor:
	cd tas/miracl; echo -e "33\n0" | python3 config64.py
	go mod vendor && cp -r $$(go env GOPATH)/pkg/mod/github.com/google/go-tpm-tools\@v0.2.1/simulator/ms-tpm-20-ref/ vendor/github.com/google/go-tpm-tools/simulator/ && chmod -R a+w vendor/github.com/google/go-tpm-tools/simulator
