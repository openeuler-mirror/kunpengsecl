package pca

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

//定义几个相关的结构体，用于存放相关信息
//
const (
	EmptyPassword = ""
	RootPEM       = `
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MQ4wDAYDVQQGEwVDaGlu
YTERMA8GA1UEChMIQ29tbXBhbnkxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMjExMTIx
MDczNjMxWhcNMzExMTIxMDczNjQxWjA1MQ4wDAYDVQQGEwVDaGluYTERMA8GA1UE
ChMIQ29tbXBhbnkxEDAOBgNVBAMTB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCbVrrC9OX4l8uIfU/oov8RjxypzG+ed9yyb3dTfViHL/30
nf4ZwxiS2gMhoJFpLCIaOt1k71GqRhFu3nR0f1gHxCVhRiHAcU8R+grmBvsKGbxs
o4qPSWzw+lk77cQihI06MRj5GuchCqT+xKXRwMHjRb/WnGX09OryPG/Qm0veQXdU
dUbHiQ7ny5g8Y6II3Lp6BGEz5OyP87lodF7C7+m4OiV8BQzINdyJPA4d7RGgx/8m
nwLusyfSIDM+Q5x1ReYrzyIZM+d6NbnL3JXcrQhaSxyHD/mG+qu6KPVRsDmAYkcy
8zJhHoSjtAj1oRReRw8S8VMcTw9V4GDwVMv97n1pAgMBAAGjZzBlMA4GA1UdDwEB
/wQEAwIBBjAPBgNVHSUECDAGBgRVHSUAMBIGA1UdEwEB/wQIMAYBAf8CAQIwHQYD
VR0OBBYEFJLKF+6Wwgf9998CBOph5bg5tKkXMA8GA1UdEQQIMAaHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAIvamsOwm882cLsPI4zBXGBZ3CI0F19dg43q1V4+xaLt
eO7uPPZT0m+YOEIbu1SjWDaJsitilM1sAP9meTq5ygf1W4uQp5W95xt/P3xo1r2f
rHtjKxnRHLxA3ChEDrfPUjDqYD6rWmM014VUbbot1r4LgaU9uJXZgHpsx8bIcgkF
z0dziLDIns3kUWB6viFN7Yb9SMQ/JmH1mFwuVFPKd2DJfeiRlrbvHDdbUwSz9dXn
GRgNe3n8UMrqrT3zJYD9BDuGFy57kOFLB3ZToZ0HZ7/hk5tkOJztvayO74mIlgun
dqvNgCig2Dmxdq4nKpPx3p+6ClUiCy/5PbtM/dTpdSs=
-----END CERTIFICATE-----`
	CertPEM = `
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIIFrl/kXlBImAwDQYJKoZIhvcNAQELBQAwNTEOMAwGA1UE
BhMFQ2hpbmExETAPBgNVBAoTCENvbW1wYW55MRAwDgYDVQQDEwdSb290IENBMB4X
DTIxMTEyMTA3MzYzMloXDTIyMTEyMTA3MzY0MlowNzEOMAwGA1UEBhMFQ2hpbmEx
EDAOBgNVBAoTB0NvbXBhbnkxEzARBgNVBAMTCnByaXZhY3kgY2EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOehd7S3PTsW+LfswbiIDRYegYk/cDiBGF
CrjHTLs35SKRYKzfS0GiMdnPhveZk/qKstQu/JeIhn9ycSBx3739v3F0ySqZQTMX
/24QWBp4cq4UlQkWa+Q/GdgXj/9OokhWeWo8aJHJVbHsMprPQ15wfleNfcYEGUYa
5Aho1finlXE/HGpfka+FQNQocO0ZqmXR6XJbMBk+3SEuWiS1jfFtFYk1POkc+Jw3
syN/foOWfH5UqV0crcxMAAbqDW2j6vyqkFfDJD1GraCm/vGySzlFpmRjTOj90K9P
wTeGzO1qLgi7OKWkiJcXfiQSjt1NDCozp1cIdCl2IP1JCZIxs+gNAgMBAAGjgY0w
gYowDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB
/wQIMAYBAf8CAQEwHQYDVR0OBBYEFHGWXhHCb0M/3712y+CSny2u3hflMB8GA1Ud
IwQYMBaAFJLKF+6Wwgf9998CBOph5bg5tKkXMA8GA1UdEQQIMAaHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAGIoIubJJyq85rNI9f+SF4TDybbdnsMnrcAt98t2fPsW
Vp2s0RYCwu5OSZDrqiiErLXlX7frgvpeEuiWU/K+ruEM6Fj3sirCUd6G2QYYHboC
eRRaEvAW7OkKnUW35dROZRaZuJ7t5+TfnCBiuxhNRutBAvnGavOX25B/k7dp6F3V
f/sJaXblpvQ8RTi4YUgkLFxUGHDmMYiDFCaqJn2hgRb1UNibshx4xMOsO8jMh7xT
zNcyYs8zM4V6wOk3T+lU/GnH4FdJQ4xKxZTqkVz3+qeq/1cl/G8PJttWM+yARTpj
8PPjY/QIa7VcWEUj9DeREBbqJFcyc5JvhOScYw4EMPQ=
-----END CERTIFICATE-----`
	PubPEM = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
-----END PUBLIC KEY-----`
	PrivPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtGHi7jpi3g2dbYVQJchq9SrfYUm1Pxq1uk2DCMzpzlzjum00
8IxlxUPNcMulLTCJJBZUMv6Wg7XMMXOPXtqgRVLAhdTelx3Uq4Bu1dE4mM7/iy9x
3BWAXjCdyXW8Bi6bPRaX/eUJ+KO/QA00jaEVsxARzNFn3bsO2JyXwVAj5BKfjDwY
gtSIuyT/tmz6S5VzGsLshCDVIkZBhOxmqOgPIr3y8XvZ53ma0kfxVl0g1vbJmRjk
o/4x6OGNLXMFlHpCaEiCQqYUbgYHdZwGHhu7lfbCPewWRna0E8nVHGR5m8yrMQ9N
UsuFjtmRJeo9ufPjrUz1B0gdZcWboKutzySAlwIDAQABAoIBAG/Md6UlhN+R2q/l
v54bUMdxcg/PakmZWWcF4aATuRnREsgaJYStz+nqsysk3NRcT7ORL1CH4GvzwoIn
2IV2xX0R5AdOv0M0FvrQ2GEnkoeLTHFMz6oTnYNDaJhTo1zFiCvdlAil638ypjeh
t5/MZjGcVRv38gNIi9QPgjMrY4NYSOhLHLiZa3rCzKw+pTnl6UrVpPOBnUWe8CtF
ntEinw1E5la+KXkqsToM/TBKuIfq9JuqPA/63hFmT80jJBb4O3jXhqCwJi7Y1yYf
d96j6ISEMowTFV0uujKU8m7tFvBa0ahW80voZEH4s0+ne28zjxcu5/z/n/gKGRGm
ywaZZIECgYEAzTvEPN5nmhlAOaoc5l6p6J3rLlQGsqcrrNvm0qr4PGQX+MQzTYJ5
EgYLIZaO5p5sxrybsguSdHItz1Nh7DY23b64uteTJYk9Aoh2+VuvwpjalItJUW/3
4s4D1YLi1pVfAw2HbkhcPba8nYpRCOOwm3vNqyMebxwcGV+OnUaQHtcCgYEA4QBy
FBoEHyD2V5jX38m7hw3uqpYVx/T/ofajVasZxw+FndXaNbB8WAmHF0YxlkOvY0di
37qrPlQeOhO0B3MY4VmVVBglwM9gJwkZPTMWCzM+aCUqp1c0LmVZD2aV3/k2riZ9
NBZRGnbQ2pJ5SkYOWh6DouH6caqZmcbYtCffNEECgYA/3XthnawLrhPoXeGEZqzk
8E+BKTC0Y4UZ04xuvjllQZicFyIH2rQmQa8xEpMBfQdIiOTCcQtwJR/QRphQU0ab
loAR1Ie7xIsxwJmVW0zEd6B9XSLBruAqugVDaemA8RaR8qHUVbwukDD9rU8uPvx0
RgBoYxNTbCHqW2wb0RuEHQKBgQDK1IMCOf2zLhzEFKWuOIYTlmyrXMbfza1QjSzq
wmZne0ehZDHkqmc9WcFtKrry0ate3PB17SoH8v6YrkBhYtFv/DjQaUBHUupD5kDZ
WZ8qk5RTgAW2ercwh+5EIt9C277+OPYvKVsNd0SJdPdgDE1N0ioqgHorU3ZKGOYr
abIdwQKBgGBIy55vZ+8BTBcvvBBYzX1iSZJ5Zxxbmsd3Lz5aG5X3y5ZmS0OEEqJT
SGusC7xrMQxcbIiy8nFsoXrBjdy5w6RfdbUF96QgtSb5Que5inDtSadhgGHqJpU+
iRPpQT815b+A3q4eUAFVBvHtD0R4cpqfAkfigoZtWWVb8onP4MES
-----END RSA PRIVATE KEY-----`
)

var (
	PcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	ParentPassword   = " "
	DefaultPassword  = "\x01\x02\x03\x04"
	DefaultKeyParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 1<<16 + 1,
		},
	}
)

type ToICandSymKey struct {
	Credential      []byte
	TPMSymKeyParams TPMSymKeyParams
	SymBlob         []byte
}
type TPMSymKeyParams struct {
	//可能还要存放加密的算法等参数
	TPMSymAlgorithm string
	TPMEncscheme    string
	EncryptSecret   []byte
	EncryptIC       []byte
	IV              []byte
}
type TPMAsymKeyParams struct {
	TPMAsymAlgorithm string
	TPMEncscheme     string
}
type Request struct {
	//身份请求
	TPMVer string //TPM版本
	IkPub  *rsa.PublicKey
	IkName []byte //ak名字

}
type IdentitySymKey struct {
	//身份会话密钥内容
	IdentityReq      Request
	TPMAsymmetricKey TPMAsymKeyParams
	TPMSymmetricKey  TPMSymKeyParams
	SymBlob          []byte //用于存放加密后的身份证明
	AsymBlob         []byte //用以存放加密的会话密钥
}

type KeyPub interface {
}
type KeyPri interface {
}
