module gitee.com/openeuler/kunpengsecl/attestation

go 1.17

require (
	github.com/beevik/etree v1.1.0
	github.com/deepmap/oapi-codegen v1.8.1
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/gemalto/kmip-go v0.0.8
	github.com/getkin/kin-openapi v0.89.0
	github.com/go-openapi/swag v0.21.1 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-tpm v0.3.2
	github.com/google/go-tpm-tools v0.2.1
	github.com/google/uuid v1.3.0
	github.com/labstack/echo/v4 v4.6.3
	github.com/labstack/gommon v0.3.1
	github.com/lestrrat-go/jwx v1.2.9
	github.com/lib/pq v1.10.2
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/russellhaering/goxmldsig v1.2.0
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.7.0
	github.com/tjfoc/gmsm v1.4.1
	go.uber.org/zap v1.21.0
	golang.org/x/crypto v0.0.0-20220209195652-db638375bc3a // indirect
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
	golang.org/x/tools v0.1.9 // indirect
	google.golang.org/grpc v1.44.0
	google.golang.org/protobuf v1.27.1
	miracl v0.0.0
)

replace miracl => ./tas/miracl
