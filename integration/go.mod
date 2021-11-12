module gitee.com/openeuler/kunpengsecl/integration

go 1.15

require (
	gitee.com/openeuler/kunpengsecl/attestation v0.0.0-20211111001126-2c4e3102c310
	github.com/go-oauth2/oauth2/v4 v4.4.2
	github.com/go-session/session v3.1.2+incompatible
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/google/uuid v1.1.2
	golang.org/x/oauth2 v0.0.0-20211005180243-6b3c2da341f1
)

replace gitee.com/openeuler/kunpengsecl/attestation => ../attestation