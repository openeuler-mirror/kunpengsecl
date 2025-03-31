#/bin/sh
osv=`grep "\<NAME=" /etc/os-release | awk -F '[" ]' '{print $2}'`
# install deps
# (cjson is handled separately because its package name varies between Ubuntu versions.)
ubuntu_deps="protobuf-compiler libssl-dev jq"
openeuler_deps="golang protobuf-compiler openssl-devel jq cjson-devel"

VERSION=1.17.3
OS=linux
PROCESSOR=`uname -p`
case ${PROCESSOR} in
    aarch64)
        ARCH=arm64
        openeuler_deps=${openeuler_deps}" itrustee_sdk-devel"
        ;;
    x86_64)
        ARCH=amd64
        ;;
    *)
        echo ${PROCESSOR} is not supported yet
        exit 1
        ;;
esac
GOFILE=go${VERSION}.${OS}-${ARCH}.tar.gz

case ${osv} in
    Ubuntu) 
        sudo apt-get install ${ubuntu_deps}
        # install cjson specially
        if sudo apt-get install -y libcjson1 libcjson-dev; then
            echo "Install libcjson-dev libcjson1 successfully."
        elif sudo apt-get install -y cjson-dev; then
            echo "Install cjson-dev successfully."
        else
            echo "Download and install cjson manually..."
            wget https://blueprints.launchpad.net/ubuntu/+source/cjson/1.7.15-1/+build/22291562/+files/libcjson1_1.7.15-1_amd64.deb
            wget https://blueprints.launchpad.net/ubuntu/+source/cjson/1.7.15-1/+build/22291562/+files/libcjson-dev_1.7.15-1_amd64.deb
            sudo dpkg -i libcjson1_1.7.15-1_amd64.deb
            sudo dpkg -i libcjson-dev_1.7.15-1_amd64.deb
        fi
        wget -O ${HOME}/${GOFILE} https://studygolang.com/dl/golang/${GOFILE}
        mkdir -p ${HOME}/go-${VERSION}
        tar -C ${HOME}/go-${VERSION} -xzf ${HOME}/${GOFILE}
        cat >> ${HOME}/.profile <<EOF
# set PATH so it includes user's private go bin if it exists
if [ -d "\$HOME/go-${VERSION}/go/bin" ] ; then
    PATH="\$HOME/go-${VERSION}/go/bin:\$PATH"
fi
EOF
        . ${HOME}/.profile
        ;;
    openEuler|CentOS)
        sudo dnf install -y ${openeuler_deps}
        ;;
    *)
        echo ${osv} is not supported yet
        exit 1
        ;;
esac

go env -w GOPROXY="https://goproxy.cn,direct"
go env -w GO111MODULE="on"

curl -sSfL https://gh-proxy.com/https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh -o golangci-lint-install.sh
sed -i 's|https://github.com|https://gh-proxy.com/github.com|g' golangci-lint-install.sh
sh golangci-lint-install.sh -b $(go env GOPATH)/bin -d v1.41.1

protoc --version
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
export PATH="${PATH}:$(go env GOPATH)/bin"

go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.8.1
go install github.com/google/go-tpm-tools/simulator@v0.2.1

