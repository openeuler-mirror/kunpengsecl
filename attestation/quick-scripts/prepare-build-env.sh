#/bin/sh
osv=`grep "\<NAME=" /etc/os-release | awk -F\" '{print $2}'`
# install deps
ubuntu_deps="protobuf-compiler libssl-dev"
openeuler_deps="golang protobuf-compiler openssl-devel"
VERSION=1.15.14
OS=linux

PROCESSOR=`uname -p`
case $PROCESSOR in
    aarch64) ARCH=arm64;;
    x86_64)  ARCH=amd64;;
    *) echo $PROCESSOR is not supported yet; exit;;
esac

case $osv in
    Ubuntu) 
        sudo apt-get install $ubuntu_deps
        wget https://studygolang.com/dl/golang/go$VERSION.$OS-$ARCH.tar.gz
        mkdir -p $HOME/go-$VERSION
        tar -C $HOME/go-$VERSION -xzf go$VERSION.$OS-$ARCH.tar.gz
        cat <<-EOF >> $HOME/.profile 
# set PATH so it includes user's private go bin if it exists
if [ -d "\$HOME/go-$VERSION/go/bin" ] ; then
    PATH="\$HOME/go-$VERSION/go/bin:\$PATH"
fi
EOF
        . $HOME/.profile
        ;;
    openEuler) sudo dnf install -y $openeuler_deps;;
    *) echo $osv is not supported yet; exit;;
esac

go env -w GOPROXY="https://goproxy.cn,direct"
go env -w GO111MODULE="on"
go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.41.1

protoc --version
go get google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
go get google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
export PATH="$PATH:$(go env GOPATH)/bin"

go get github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.8.1
go get github.com/google/go-tpm-tools/simulator@v0.2.1
