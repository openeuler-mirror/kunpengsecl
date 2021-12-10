package pca

import (
	"crypto/rsa"

	"github.com/google/go-tpm/tpm2"
)

//定义几个相关的结构体，用于存放相关信息
//
/*
const (
	EmptyPassword = ""
	RootPEM       = `
-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MQ4wDAYDVQQGEwVDaGlu
YTERMA8GA1UEChMIQ29tbXBhbnkxEDAOBgNVBAMTB1Jvb3QgQ0EwHhcNMjExMTI1
MTcxMDMyWhcNMzExMTI1MTcxMDQyWjA1MQ4wDAYDVQQGEwVDaGluYTERMA8GA1UE
ChMIQ29tbXBhbnkxEDAOBgNVBAMTB1Jvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCoE7EqJKDx+qkp09LiqsJ24T5vTXUa2D55Zk/e+/8JJMwZ
MByvzXgXSfa9Lb2wSJnBHwhQ8vE0rR9WnIp2Njpiji3OEbcetBUqMbAVmHPMnbvk
SyBPh8VnAU1tf9qvg+DAzU7+BHjt40cuI30FtvAYxTqkXB32LPxeb2ISegZtt/tn
r9KOndrq4DVsgiwqSu6lwekK523M+yekvWwSzwnv+vyNM8Jrbpc5y7PsgcMH0CZA
JaIZi9oRz/L9w71j2xKPcIm4xCJ8C//atefPxxVsOiTomLKl7q7DMALf0sEoikLR
e/Uvr/gJKN67qIzl9oBJYeFGQR6ohGveHJBI8JyrAgMBAAGjZzBlMA4GA1UdDwEB
/wQEAwIBBjAPBgNVHSUECDAGBgRVHSUAMBIGA1UdEwEB/wQIMAYBAf8CAQIwHQYD
VR0OBBYEFIzbDkn8lcpTK5zYyaDL2OHVYSdRMA8GA1UdEQQIMAaHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAB+k4Bpu5PISRSOfah0WyRhnS2V8B1ulAmJRH8PRhs5q
6Z7IgLJ1Pd8/ZcAVwNHzOxWie0xrFUnfG0I+ChRu7fUbIxCxFlXduFhRj7aG/PqR
dP/nccHecYMJhkOXYvSROe5PdrFpade+u69SvQMoHUG8CNnkbLDhMjXg/czs4nid
tk+DKi993Teu0gkL7iYmcHApJVVcevzom7LA/1b4P/ei7rYyGJQv6VZYQszKzMWm
kwoNjsdS9ok6sGj6d4rsj951wiTGdYh2UKw45Hy7j/sXqBCVW0RiwOxsCuUszOhk
QTiqejJL+M0MY76/c8fh3LJgBWq+sbvHQALO0czseqk=
-----END CERTIFICATE-----`
	CertPEM = `
-----BEGIN CERTIFICATE-----
MIIDfDCCAmSgAwIBAgIIFrrZNoUze/IwDQYJKoZIhvcNAQELBQAwNTEOMAwGA1UE
BhMFQ2hpbmExETAPBgNVBAoTCENvbW1wYW55MRAwDgYDVQQDEwdSb290IENBMB4X
DTIxMTEyNTE3MTAzMloXDTIyMTEyNTE3MTA0MlowNzEOMAwGA1UEBhMFQ2hpbmEx
EDAOBgNVBAoTB0NvbXBhbnkxEzARBgNVBAMTCnByaXZhY3kgY2EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUaGoa/IC1Yv5en07iepZz1ZXQU/R4qSrw
AU900QpbuQd8bbLEoZLegnmpL9XbvDNs1fnIgLUe8FOVdpjU1ay+MrtdjeaSdi+4
KomPrOk7yGMwOcvm24M16h2C+CSbM9IN9r8tY9aSH89FcImBRaMj94bvifEgZJTW
9WCjIKvGLUvPwHweCEBPsoDzsLjrzbh/FADnUUSAjiCz9GLL/M4rIm5ruKsXxFnk
UhC8xtBaelLPeTAXh+MENa30ogKrBzdCyl5J45aMi2iNnQEgTpY8fHMU7M5gpz8N
5RIa3SfeGlL2PanG7VQJZoq8I+VauBhhAm9S8ir1lFVMXQITLk8TAgMBAAGjgY0w
gYowDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB
/wQIMAYBAf8CAQEwHQYDVR0OBBYEFJfqV0giTSF/+ia5L0roESQUHI+sMB8GA1Ud
IwQYMBaAFIzbDkn8lcpTK5zYyaDL2OHVYSdRMA8GA1UdEQQIMAaHBH8AAAEwDQYJ
KoZIhvcNAQELBQADggEBAC79DntVfo1+Kd3nOFrWnFYlgrigljvX6iVXdVZbAJN7
5zQammljJClb91cRlh9CkMHjQ1/4eE6AHjK0uk4AY214SmQWLyax+wA8lUI9TAvG
HZghU3uykm5Um00bdPsLbUDiYIUSwTxj1q+Zv/lOduD/ngXAj06uWMfYPSwQGteo
4YMFann4yEu9GxgaK6H7DHWpdLyaMifRiONokYFtZV6Z2muqjxob5bMXZjIx0XD4
E5F46bNQVSqnIYh10O+KJLv3JTfeUL4ZUN/QnLXQHr5mCDuuWjKtOi0dOwXuO/gE
1Y3a/ZeS6ogt+clTLQ0KfYzZormHo3VcL6eIQHHAwfE=
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
	RootPrivPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqBOxKiSg8fqpKdPS4qrCduE+b011Gtg+eWZP3vv/CSTMGTAc
r814F0n2vS29sEiZwR8IUPLxNK0fVpyKdjY6Yo4tzhG3HrQVKjGwFZhzzJ275Esg
T4fFZwFNbX/ar4PgwM1O/gR47eNHLiN9BbbwGMU6pFwd9iz8Xm9iEnoGbbf7Z6/S
jp3a6uA1bIIsKkrupcHpCudtzPsnpL1sEs8J7/r8jTPCa26XOcuz7IHDB9AmQCWi
GYvaEc/y/cO9Y9sSj3CJuMQifAv/2rXnz8cVbDok6Jiype6uwzAC39LBKIpC0Xv1
L6/4CSjeu6iM5faASWHhRkEeqIRr3hyQSPCcqwIDAQABAoIBAGHldl9xjjzjHvy5
4C8d/r53W4JAv2Cva1QSf5sFc/rDcA2LtGnBZ51I+2oc5ktzPfr6NEHR/yQLYiF0
dEF+PGuDHLLWJq6/fURiRImPjoMzrGjASUWJczUX0R1iRuHMEnC6JLRXrogAxUje
aseVUitbVVi+PsVQVn46qgjRAkWM3fGD9ym3NiSbNbHFPJfchw1DAZzh5rhfP34F
2y8tqBrqw8ei9whbOPPjG2K1qS87QWh2vD71qntViu0KtIjqLYJbi4UohaXm18Wt
gAP4V6qjlHsvhkaTQtari7yZwZjGXWJLwAxyo0AAsvJ3ikfmeSe7xrfz0nkQotb7
vPZreuECgYEA2ksw83VMcpz/iEq3qZqmpiepYyQ3gfixG+71biBK2baFRcFAZrZ3
Zr2JJpmCVciOaG2I8g8/fPPCg3Ft7IKpXMJjf8BicFoKgA01OIEBkyZ38SkPCWKQ
64K4GUjAxwsocWM2CMM2jWGLZDuAP4z8PWd1oNQamCcgPFbWHxM4zE0CgYEAxRvy
Ps13Em+CIFDnks9tIuW8yS5sS7Cf1gXY/dVFO5FnISU8XE0260fJu50VgVVwXFbP
MjcVtanDCEA+8xyz6DQONOny8IODzvZuN5m4hw3pezGnwAY4OUXl6NaHyCXb/uxS
Fjeb8ZJQ0SdtZpgzhw8sBwNsOtLQZvQQXIoVKNcCgYEAw4tFn2E9CRKQaTOdUKYD
kKXIu9HOk3QGm2I0ouD0jBBPVEwn95qOXQ9+E4DB2zxcLTmpykRUeAcYAI0UjiAB
vOE5JlBdHg3aiBjMyv/tPDbijLpeCOctsHqZlbSxU9wv71qTJchRTtbJehE+8i7G
Ke9K1LYL2K571vFmv9GFOKUCgYB/HP6kMazQXsj0PjiZHNus3atZsm50gXsScsL1
L0xuld6EKZc7jzATm0AllbAAsDC9293S7GM7vDbiY0w1TBVZcfiXdygMo0OlfJan
lKLDtd0UbXlZBKnNhZ43AeKe2It/YretTD9tEoa720laGF1ihA5Il5R8euea/Vpv
0zzCEQKBgEqb/Ta7FAffL6AV0Q1tiPLucH57B5lyzJ4tr670ZCZhXcHr7Nz2f5l0
eGSoIZjNOrTuwvmX/lOlsZcKZeaRBg8zfOw7F/GYnZBQHneGJzzpOgm9dXoBye9Z
eJPDRQbU9c9TCZEmxrwAS+kNpUNBLBZM/ffEzt2e3ycpI5Y5o0Jn
-----END RSA PRIVATE KEY-----`
	PrivPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1GhqGvyAtWL+Xp9O4nqWc9WV0FP0eKkq8AFPdNEKW7kHfG2y
xKGS3oJ5qS/V27wzbNX5yIC1HvBTlXaY1NWsvjK7XY3mknYvuCqJj6zpO8hjMDnL
5tuDNeodgvgkmzPSDfa/LWPWkh/PRXCJgUWjI/eG74nxIGSU1vVgoyCrxi1Lz8B8
HghAT7KA87C46824fxQA51FEgI4gs/Riy/zOKyJua7irF8RZ5FIQvMbQWnpSz3kw
F4fjBDWt9KICqwc3QspeSeOWjItojZ0BIE6WPHxzFOzOYKc/DeUSGt0n3hpS9j2p
xu1UCWaKvCPlWrgYYQJvUvIq9ZRVTF0CEy5PEwIDAQABAoIBABWoF7lsqUrVLw5C
u+5HhXOGAWJeTPzIcsJJv+ovLhkwAl1jaei2eJ0LPJBNekaPJ8cfAfq5dL4UztDc
aLS6nIQ/8+6T+0BPoInsfF4TySv5QHO4UNvW4cfreNrTphfU7sPRtqhQF56Kc72m
vb5adUnDgRSHQfiFiM9p8VJwkFMCN7t+DX5dUCitkXrkecSeB7Tv+GWsnqoTkaUS
qboAzVaXfuHVYxId7UQ5ZioolcxNR2Vg2PsQGOpYXWcl+pPp5jzZA89GYt40sZ85
YOsKmd4S4ayN5oh24p7tROi+/DQ5xsQlfZV+oWfuqbfzYWixqiuF5Im7Y0mEwnUw
MWyNc3ECgYEA7WxnVJnH/g3azmOWuX0KS76joyGo7hINlLPFHwTc7lFE6Zvc5mgQ
YxDvu/bwWI8jhcMJji0uSC5oQeOIyJFFAk9k2rhmfqujQVFJOjWh8XYjNbLKLBBd
g46py5T+/m4H7KhHnBKFlqJGf4bdcYytGrg3zM/mICM53h/OCZR0DxcCgYEA5Qby
v0rUMwJolkVlI/C5msP52tXwgRWcEMPes9pWOdSfeUR4MwsnTno+w0f+KSTylrJ4
bjKkPLlnD/vSIW6QFs8bAq0Q0YPnArBzVy7jUXV7WNYVViK4Gw3VJGy9QP3Tm1TF
VMYY3AfhEopcsqIsSgH6rPJ1+VEWWRAbKzD/XWUCgYEA3Bl5tVkWqPOJG3oBWZWM
fOmPY4SpyYIc6vS40ee9NIVMoFBouYRRZLVnuVXUPBT+Nlu3uQEzfaDf7+0SefUK
B3k4ovb9tYJCRyQnAXqE1YbSX06O08icGICh8eP/fDjeycq7D/mvtBRdzI1nLoPe
Wf3bZNh6muJtG/laFVF1QiMCgYAi95qcZjpbx2RcfR/iCuDrpjxBkyRzMO9xB9a6
sv0zOylWBIQtluhbbQKkIhvGAGQhagJFIOo+czgvEo2UmSLauKgxEmdc9byRhos1
pm0ChONePuFnE0n0p3oBY7DJeXeTYa/3L3+gKHvOrt1UULpeWksBmMs2U5EL7A+Z
2pNCmQKBgDRoW3RIWfukTicCreWfc+eROW3EddtZ0CYFAEoWj3Dw+F0XAVgV0Oql
x46uyuz0ARUkV1UsTtwQwz9BPBfnbn/Lh1MS75sqkjBQt9z0H8eIjcNaUNz51TSv
1snwfscp0EVffdY53PP/zBfvblxL0GdgaFGBaM4uzpNUImxKybxk
-----END RSA PRIVATE KEY-----`
	PubRSA2048 = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAojniaigqr3RlJ2EfmiS4
WO7rrfX4gzREwQh3nTgo03keWmRmM7z+VCHztlNWmeRTOmwtbR6tMYCFadpESG+K
PTaYMmFi42HTTp9hDtyIdyBlr2T06qv2GuLxP8vU7udZipE+dSnLt1q+cHdhG34M
TB7Ewmp6pJImygspsopW17f+pP6TaTpULwejb+2pJl+6e/PiQiulO420+ug/9kms
PDi+G/elm40gKjqo9vBtN4sWnTxDFhD+IBoEYJBxAZhfKkz7TKeHLSFo1uSiG/Jj
bibTTzlA29xPeQCGKHsWiH1Z+XR4eMUC6KLmu3oaAHMoafUx060xgfQdkMtxJ+b1
MwIDAQAB
-----END PUBLIC KEY-----`
)
*/

var (
	PcrSelection     = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{0}}
	ParentPassword   = ""
	DefaultPassword  = "\x01\x02\x03\x04"
	DefaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt | tpm2.FlagRestricted,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}
)

type IKCertChallenge struct {
	EncryptedCert []byte
	SymKeyParams  SymKeyParams
}

type SymKeyParams struct {
	CredBlob        []byte
	EncryptedSecret []byte
	// the algorithm & scheme used to encrypt the IK Cert
	EncryptAlg string
	// the parameter required by the encrypt algorithm to decrypt the IK Cert
	// if encryptAlg == "AES128-CBC" then it is the IV used to encrypt IK Cert
	// together with the key recovered from credBlob & encryptedSecret
	EncryptParam []byte
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
	SymmetricKey     SymKeyParams
	SymBlob          []byte //用于存放加密后的身份证明
	AsymBlob         []byte //用以存放加密的会话密钥
}

type KeyPub interface {
}
type KeyPri interface {
}
