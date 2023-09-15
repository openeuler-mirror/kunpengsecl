package client

import (
	"io/ioutil"
	"os"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi/server"
	"gitee.com/openeuler/kunpengsecl/attestation/tas/config"
)

const serverConfig = `
tasconfig:
  port: 127.0.0.1:40008
  rest: 127.0.0.1:40009
  akskeycertfile: ./ascert.crt
  aksprivkeyfile: ./aspriv.key
  huaweiitcafile: ./Huawei IT Product CA.pem
  DAA_GRP_KEY_SK_X: 65a9bf91ac8832379ff04dd2c6def16d48a56be244f6e19274e97881a776543c65a9bf91ac8832379ff04dd2c6def16d48a56be244f6e19274e97881a776543c
  DAA_GRP_KEY_SK_Y: 126f74258bb0ceca2ae7522c51825f980549ec1ef24f81d189d17e38f1773b56126f74258bb0ceca2ae7522c51825f980549ec1ef24f81d189d17e38f1773b56
  basevalue: "15a38f450be38bcc8d62fa352bc5c33035d72b6964c227a0a6bbabf1d8de2a07 2a5629919ce34441577741b0c202dab37809eb41c1d0341fb27f2c1e567b4a31"
`

const (
	configFilePath = "./config.yaml"
)

const (
	asCertPath = "./ascert.crt"
	asprivPath = "./aspriv.key"
	huaweiPath = "./Huawei IT Product CA.pem"
)

const ascert = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIURBG3rzn2SH3wruHaPKctA2pEqS8wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEyMTcxMzE3MTRaFw0yMzEy
MTcxMzE3MTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC3FM8ErX6+Vcy4sf4DQexeLDRFrqaKOWEEi90MTjE+
aAuIV0Vy8tFgnvaVoznLD6J7LUhaT1xvVNEhsQpSp+BEdZ8kUtxNm91j4FBDE+V6
RxWbGPXcZhfVSmoc+dlwt5aCrAH03GAJOp6NWLBGA6LBN1X5yaT6hJJTq3ioC+K3
h/08Ub801Glnai4BECygUHp1qn7bFl9p2o5yRfL80MJxQKsq1dKvUY/+Dsxzdwcr
GVT68nstBjXbnoTAjyhIZepJvZmGKvoiEG0sQwi3dInEK5Q9QLZBAHPNS+M/3v9g
dW/F1QPYeFEtz7+Np9gUYs9GOkB5L6Cr+gXeFRfRiO1/g9BMzrFhkKYTgnLHpdwu
oWpDmmfcr8TcRgSZCZ9oAC41wcn5b8nuGNUbI8fGRKaDzEsprEID5gOVofsC2KZv
sD+9ATI3MBD95OKXIbE0zMaAx21EIUxe7HVWUTcNnHf9kBpVR8x27xa/AV4Qc89d
1pCYg0cm/4SpkuhzfP1VGdL935QQcVumR85nBNyX4l8c8239zbnIepUn8GzkRqi5
5dwqLzxAY96y2VYNT3pbuRd3qK+psuPlviSZ/NtebFETjzVbl6LRCsKmY2DknfBo
LyIEO7M06H6B15lbZjPEd0vil4R9gROl/7h9k8wP8rj68/BiCE32xvsXRyy5oDt4
bwIDAQABo1MwUTAdBgNVHQ4EFgQUv+5bJBMwfJN9pB0XhB+niXZu6lowHwYDVR0j
BBgwFoAUv+5bJBMwfJN9pB0XhB+niXZu6lowDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEACAIBde61vKD3PBLiYmgFtXErnRIkGm9EY8q/T74xv9vX
b04mry+LUHAKDx/M2wpfcGW2rAGaNGvgGvfhK/vKv9P7gNmIjZOGgSJm+lsKCr39
2NlROMsi08GGWRBQhZNEt5feaH5bcCGWjDHnNTL1Nhe/OOf1i74X7gX3WS1mD0O+
I9/TUznmNg7bZhICRswFHEymSHMxyOsvzG+f1ENUr6XKgXTWD89PNOJ0IzQsXq7V
W96YSM7EvW87AXWyioFi7B9TRHtSxK+/ZJz5joZos8X4/Yamve7OpX3jQnrxxh0W
vkNdJ1fiiYzEciyTHAVUTA1q/ZqewEUgVZYhIAbTCEV1h1PLrL3VHbzCrarWZqX1
+vSDOJoYBtAMfugcsYqgnIdYOSwpQjdan8rXIqhgk2rwAgmIjEWvRAvFhoOxO7Os
PhLgoeJo+JahmUjAfE8L/wW3k/3OJQy2eD+cAtUFWpOdMrmE5FtepUv6voM6N6Fa
Q+d69RUiN0XvVYlG/ZXIeHtPYk6cXxof7J3Tn8ieEKbT7OwuG7vxRodCGSao6o3i
uOdEBUnNkMadj7i265D8de8sOuQ7+pPu4lNBZGmF5XeaBEEynF8ts1rWrwM+lUgK
/bK1vXGMemom0NEsj6zAOd2GUBuhFP9WLYXh4SRTY/5PKVhAdL9oenaIxji99lQ=
-----END CERTIFICATE-----
`

const aspriv = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

const huaweica = `
-----BEGIN CERTIFICATE-----
MIIEsTCCApmgAwIBAgIRdjl5z9FobnagzdStBIQZVIcwDQYJKoZIhvcNAQELBQAw
PDELMAkGA1UEBhMCQ04xDzANBgNVBAoTBkh1YXdlaTEcMBoGA1UEAxMTSHVhd2Vp
IEVxdWlwbWVudCBDQTAeFw0xNjEwMTgwNjUwNTNaFw00MTEwMTIwNjUwNTNaMD0x
CzAJBgNVBAYTAkNOMQ8wDQYDVQQKEwZIdWF3ZWkxHTAbBgNVBAMTFEh1YXdlaSBJ
VCBQcm9kdWN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKE3
0649koONgSJqzwKXpSxTwiGTGorzcd3paBGH75Zgm5GFv2K2TG3cU6seS6dt7Ig+
/8ntrcieQUttcWxpm2a1IBeohU1OTGFpomQCRqesDnlXXUS4JgZiDvPBzoqGCZkX
YRw37J5KM5TSZzdLcWgxAPjXvKPdLXfxGzhqg8GV1tTboqXoNEqVqOeViBjsjN7i
xIuu1Stauy9E0E5ZnSrwUjHc5QrR9CmWIu9D0ZJJp1M9VgcXy9evPhiHoz9o+KBd
fNwt4e/NymTqaPa+ngS/qZwI7A4tR4RKCMKFHJcsjaXwUb0RuIeCiPO3wPHgXmGL
uiKfyPV8SMLpE/wYaQIDAQABo4GsMIGpMB8GA1UdIwQYMBaAFCr4EFkngDUfp3y6
O58q5Eqqm5LqMEYGA1UdIAQ/MD0wOwYEVR0gADAzMDEGCCsGAQUFBwIBFiVodHRw
Oi8vc3VwcG9ydC5odWF3ZWkuY29tL3N1cHBvcnQvcGtpMA8GA1UdEwQIMAYBAf8C
AQAwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQSijfs+XNX1+SDurVvA+zdrhFO
zzANBgkqhkiG9w0BAQsFAAOCAgEAAg1oBG8YFvDEecVbhkxU95svvlTKlrb4l77u
cnCNhbnSlk8FVc5CpV0Q7SMeBNJhmUOA2xdFsfe0eHx9P3Bjy+difkpID/ow7oBH
q2TXePxydo+AxA0OgAvdgF1RBPTpqDOF1M87eUpJ/DyhiBEE5m+QZ6VqOi2WCEL7
qPGRbwjAFF1SFHTJMcxldwF6Q/QWUPMm8LUzod7gZrgP8FhwhDOtGHY5nEhWdADa
F9xKejqyDCLEyfzsBKT8V4MsdAo6cxyCEmwiQH8sMTLerwyXo2o9w9J7+vRAFr2i
tA7TwGF77Y1uV3aMj7n81UrXxqx0P8qwb467u+3Rj2Cs29PzhxYZxYsuov9YeTrv
GfG9voXz48q8ELf7UOGrhG9e0yfph5UjS0P6ksbYInPXuuvrbrDkQvLBYb9hY78a
pwHn89PhRWE9HQwNnflTZS1gWtn5dQ4uvWAfX19e87AcHzp3vL4J2bCxxPXEE081
3vhqtnU9Rlv/EJAMauZ3DKsMMsYX8i35ENhfto0ZLz1Aln0qtUOZ63h/VxQwGVC0
OCE1U776UUKZosfTmNLld4miJnwsk8AmLaMxWOyRsqzESHa2x1t2sXF8s0/LW5T7
d+j7JrLzey3bncx7wceASUUL3iAzICHYr728fNzXKV6OcZpjGdYdVREpM26sbxLo
77rH32o=
-----END CERTIFICATE-----
`

var (
	bufferDAA = []byte(
		`
{
        "signature":    {
                "drk_cert":     "TUlJRWtqQ0NBM3FnQXdJQkFnSVJFVk9HdExqeldMKzk2WEpGeWlYSVEwOHdEUVlKS29aSWh2Y05BUUVMQlFBd1BURUxNQWtHQTFVRUJoTUNRMDR4RHpBTkJnTlZCQW9UQmtoMVlYZGxhVEVkTUJzR0ExVUVBeE1VU0hWaGQyVnBJRWxVSUZCeWIyUjFZM1FnUTBFd0hoY05Nakl3TkRFeE1EWXpOVEF5V2hjTk16Y3dOREEzTURZek5UQXlXakE2TVFzd0NRWURWUVFHRXdKRFRqRVBNQTBHQTFVRUNoTUdTSFZoZDJWcE1Sb3dHQVlEVlFRREV4RXdNalpRVUZZeE1FdERNREEwTVRjNVZEQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU5uOGJ6SXJneGFBNFh6RkZYSzhZYUhOVU5IZ2hoRzJZeEg4Znc4a0lTL1BaY3NkZXo2WTVLZ3BNVDJ0ZTRkVkpYa2FDeFVld1IxZm1Vb1AwZStsaWtYeVlaZm1xeDF6SVZoazRtM2tuK0lYN3g5c3RMeitvR0NaYXg2MXMrdURhNnBITGN4VDVKWUZZaFVHZ2FlbE1wS2lxamEvSFo2aHRCUW1oZ1YvNFFxTHl0ellKSlc2ZVFoRnMrQW9URUx5RmFBa0JXUlkzaVFRbE55NmhsV2xGa0xUQkdYSWYvZ0E2MmgyeE5wd3BPVkdjRi9mL2ZrdTBlR3JVZHVZUG04YVRlNnNITzZIOVdhY0xwU28wd1Nqc2hoME8xUzdrcWVJUTFLdWhDY0lkQnJKRWNyalA5RFUzQnJweGxzck5JKytHeTV0ays5Q3RZTzVsTktVbTJHUVpDUlZKaDFxUWNXb3hQWTZUYkNJZTZiMi9oaFJGdHVJM2VYcGczLzlmWW1NYllKb3ZTb1dxekErUzZCL092dmdCVjFhNzNod2kvQldiWjg5bWM3WG52S3I1MVBFeUIrTnMrRUpxczVXWTNnVy93VWlmajh3VWVSS2VqV3hnQzVwSkJVRzlPWWNyc2JZaExzdFAycHdvSHFaK2RFa1kxbytPY2hvWm5XYVl5ZHdYZDgwQWNiNWNkOU1RMUgyc1ZkMUxUb3BXMEt2SGhHUVE1OE1rTVFVSWdPRjVXam1pWExVc0NhcER3bHZrREdwc282UGFpN3VRTmZFOS95TjZRWlg4VXFscE5oNTAvVzcrK0ZrNUtKWWE3b1lDU2Q4Zk9tVElHTFpuUWRxNUFTWlZWM0d4Y2RxUDVGcmdwVVIzUUIvT3dUNzdWZjhMNlJBbjg0aU9Ec2ZQREJ6QWdNQkFBR2pnWTh3Z1l3d0h3WURWUjBqQkJnd0ZvQVVFb28zN1BselY5ZmtnN3ExYndQczNhNFJUczh3Q3dZRFZSMFBCQVFEQWdQNE1Gd0dDQ3NHQVFVRkJ3RUJCRkF3VGpBb0JnZ3JCZ0VGQlFjd0FvWWNhSFIwY0Rvdkx6RXlOeTR3TGpBdU1TOWpZV2x6YzNWbExtaDBiVEFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRveU1EUTBNekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBSFc1OWZtTGNVMmQraWNuY2FHWGVoU3JlSEVjUThVbWRYWDE1a3E3eStnWTNJZklpTUgxSUNNVFZLL1hEbFZZR3ltMXFvUXdiV3hPSi9GOEFnOEFZVk1YcVpHZWtRRThCZGZNTk1tQmdnOWh6R3VoWEl2K2xzN3g5dVJBbEpEVlYyNWtOOWFNWC82RVBZNmk5cUgxTzlKdzdRRWd3T2JlTE5FM1VaY245bE90Q1BXZFhnWENROTlnNm1iSTA3Sng3Zlk0UStzVUpOQkxqNDVicy9JSUNjUGpBUS9HYjd6NEhScEtDREIzU3R6NmZaM0hjUlZiVy9BMmN3MUh3UDI3bXBuWXE4b290d216S1lydFpzbCs4YjhYQnFvME1zbWlYNmpHcTFJSi9hdjNDcUMxN0VGK2NwU3RrbXZacWFlZGdaVndPc1M2ZG83MXh4K0JnUFZlMnpnPT0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "drk_sign":     "JHaNmOryJBMjKZvMzn3fjevD-DBTpfejTxktYo9yPKry4JmVjjaRJL3f8hRGUaY49hRwukL4oWuqHnfD4pnbtvUzlqrmJmm3v6j8BtOMik0cOnL_54UGjq7G2z8J-Fe-nREuDfa5FKpBBN-Vt9LpRfbHFJdGTJlPkdvwVSUmWUC97pDN4rBM-ZQAU1poyycHHCGbLM8SxoWA-BzQHwIrowBjLtNPJ-EWHFoVK2VrYI1yX1wK_6_CB0f-4w7y2Lv2c8oxyS52Up2w69E7eMlWUn21VvBw4hInFto0H6uT-PC5sTxjOctLvIUT5VCuHQx4LGLRT90j4I2C23mQmEMZI1YPxBGx5gNUI8zv5aZBnRVLME_UoBFp3j3aM1Varkc1eh1i-Bs3eT2TRw3MUYjPYiLwYo_O5sGdCA23OPEqo1Kl53gGYIMZa5uS4udNJeAtdQrQerldz0Yt8Fo5oInz-zBmiQAY9T3SGIQr112qRL9QK-Msfn0onS2RTymxzk2ALBXUbX8hFrWmY07aBea-HbbOFfs0W0DXuJN2um_RTWUOUf7tDbDjNIlaiOidUf8Li0AMlWAu-Sgqr1ackfnq0MwQOoSd6BXqaFnH9RSQGjy3d8E_hD7BFkHr-3diqJ9x-Ie-pvIFcedv4C-jqlJhAuse0jB1nigkIae8u3xL18U"
        },
        "payload":      {
                "version":      "TEE.RA.1.0",
                "timestamp":    "9223372036854770000",
                "scenario":     "sce_as_with_daa",
                "sign_alg":     "PS256",
                "hash_alg":     "HS256",
                "qta_img":      "FaOPRQvji8yNYvo1K8XDMDXXK2lkwiegprur8djeKgc",
                "qta_mem":      "KlYpkZzjREFXd0GwwgLas3gJ60HB0DQfsn8sHlZ7SjE",
                "tcb":  "",
                "ak_pub":       {
                        "kty":  "DAA",
                        "qs":   "QAAAAP9tjoY4PBDyD0jYoox0nJ3Xhura3xVPu7Xy3hGLRC30RzQF1oZsXoKzGec9Hiad46dEZh2JAvewQ5LGHaipiHlAAAAA4YVQ_aQLNwEbzrQc-EqaNAHT8lfLq7vTJfTfHAAyDgzZCRpxbYK0DZ-ZmFHjwNiFtVIZwjtUAacSx_LQwPxEyA"
                }
        },
        "handler":      "provisioning-output"
}
`)

	bufferNoDAA = []byte(
		`
{
        "signature":    {
                "drk_cert":     "TUlJRWtqQ0NBM3FnQXdJQkFnSVJFVk9HdExqeldMKzk2WEpGeWlYSVEwOHdEUVlKS29aSWh2Y05BUUVMQlFBd1BURUxNQWtHQTFVRUJoTUNRMDR4RHpBTkJnTlZCQW9UQmtoMVlYZGxhVEVkTUJzR0ExVUVBeE1VU0hWaGQyVnBJRWxVSUZCeWIyUjFZM1FnUTBFd0hoY05Nakl3TkRFeE1EWXpOVEF5V2hjTk16Y3dOREEzTURZek5UQXlXakE2TVFzd0NRWURWUVFHRXdKRFRqRVBNQTBHQTFVRUNoTUdTSFZoZDJWcE1Sb3dHQVlEVlFRREV4RXdNalpRVUZZeE1FdERNREEwTVRjNVZEQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU5uOGJ6SXJneGFBNFh6RkZYSzhZYUhOVU5IZ2hoRzJZeEg4Znc4a0lTL1BaY3NkZXo2WTVLZ3BNVDJ0ZTRkVkpYa2FDeFVld1IxZm1Vb1AwZStsaWtYeVlaZm1xeDF6SVZoazRtM2tuK0lYN3g5c3RMeitvR0NaYXg2MXMrdURhNnBITGN4VDVKWUZZaFVHZ2FlbE1wS2lxamEvSFo2aHRCUW1oZ1YvNFFxTHl0ellKSlc2ZVFoRnMrQW9URUx5RmFBa0JXUlkzaVFRbE55NmhsV2xGa0xUQkdYSWYvZ0E2MmgyeE5wd3BPVkdjRi9mL2ZrdTBlR3JVZHVZUG04YVRlNnNITzZIOVdhY0xwU28wd1Nqc2hoME8xUzdrcWVJUTFLdWhDY0lkQnJKRWNyalA5RFUzQnJweGxzck5JKytHeTV0ays5Q3RZTzVsTktVbTJHUVpDUlZKaDFxUWNXb3hQWTZUYkNJZTZiMi9oaFJGdHVJM2VYcGczLzlmWW1NYllKb3ZTb1dxekErUzZCL092dmdCVjFhNzNod2kvQldiWjg5bWM3WG52S3I1MVBFeUIrTnMrRUpxczVXWTNnVy93VWlmajh3VWVSS2VqV3hnQzVwSkJVRzlPWWNyc2JZaExzdFAycHdvSHFaK2RFa1kxbytPY2hvWm5XYVl5ZHdYZDgwQWNiNWNkOU1RMUgyc1ZkMUxUb3BXMEt2SGhHUVE1OE1rTVFVSWdPRjVXam1pWExVc0NhcER3bHZrREdwc282UGFpN3VRTmZFOS95TjZRWlg4VXFscE5oNTAvVzcrK0ZrNUtKWWE3b1lDU2Q4Zk9tVElHTFpuUWRxNUFTWlZWM0d4Y2RxUDVGcmdwVVIzUUIvT3dUNzdWZjhMNlJBbjg0aU9Ec2ZQREJ6QWdNQkFBR2pnWTh3Z1l3d0h3WURWUjBqQkJnd0ZvQVVFb28zN1BselY5ZmtnN3ExYndQczNhNFJUczh3Q3dZRFZSMFBCQVFEQWdQNE1Gd0dDQ3NHQVFVRkJ3RUJCRkF3VGpBb0JnZ3JCZ0VGQlFjd0FvWWNhSFIwY0Rvdkx6RXlOeTR3TGpBdU1TOWpZV2x6YzNWbExtaDBiVEFpQmdnckJnRUZCUWN3QVlZV2FIUjBjRG92THpFeU55NHdMakF1TVRveU1EUTBNekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBSFc1OWZtTGNVMmQraWNuY2FHWGVoU3JlSEVjUThVbWRYWDE1a3E3eStnWTNJZklpTUgxSUNNVFZLL1hEbFZZR3ltMXFvUXdiV3hPSi9GOEFnOEFZVk1YcVpHZWtRRThCZGZNTk1tQmdnOWh6R3VoWEl2K2xzN3g5dVJBbEpEVlYyNWtOOWFNWC82RVBZNmk5cUgxTzlKdzdRRWd3T2JlTE5FM1VaY245bE90Q1BXZFhnWENROTlnNm1iSTA3Sng3Zlk0UStzVUpOQkxqNDVicy9JSUNjUGpBUS9HYjd6NEhScEtDREIzU3R6NmZaM0hjUlZiVy9BMmN3MUh3UDI3bXBuWXE4b290d216S1lydFpzbCs4YjhYQnFvME1zbWlYNmpHcTFJSi9hdjNDcUMxN0VGK2NwU3RrbXZacWFlZGdaVndPc1M2ZG83MXh4K0JnUFZlMnpnPT0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "drk_sign":     "0HbdRwbUdPKtIFH8tCNioT50pDhT4TFwi7HPCZEdyBaFBEjK9HIRNiiX9x4QXTMdgW7-jo2-Z0fvzd9a9mgOzdXBSkT-8277Hvzq_yxMsVUlsrRU2oXpMWJFXDdlYu8piMftr6VGRg8M0Vy5Tr0O0PP7CpRujklkGgDkqNScpNO7taI8Yn44saEvGhR3P0MluC9MsvVQRQiMk1mmbgyxFpYo-NHBNam5G67Az55CqmdmSGE88qQAhBnRc5bp4pubpVlsA0Or7SG6QMHHq0Tx9pbXjlgcVtNDz7cmXSX7ITZ3p8kcq5vy3RLV3JdXN454e356KmOjhZlCeoRw_fHl1h2lfroUWqQbDpB_FBp5hsNCtqNa94x-J8OM-VvryKrmp-anwqx4RJ3b4FVwtTRU_2EIfgPeidU1Uh2sbdTKkhLw8msf215NfcgcN9J-nPhQtjsUhfjUiYDpbDILqiBabn_VIf0MckyZXdQSD6TKvctOY7SesMUhRx24f3LFOSmIH1yLlu7celsKr5zfDvO4lH4g_HdxlYzJRdM33EE13xkXohGCrpLyjJ4hbP7nrmwKpGJNdM6GcHQj55UowUkCkuFlZfZJz8r3iPUwcg1Gb8SqLqvP1MLAxO7O4JwccdiR8uNo-iEug796_AmOsvqRhiH9oF7V1xa3H84ry0RH-ME"
        },
        "payload":      {
                "version":      "TEE.RA.1.0",
                "timestamp":    "9223372036854770000",
                "scenario":     "sce_as_no_daa",
                "sign_alg":     "PS256",
                "hash_alg":     "HS256",
                "qta_img":      "FaOPRQvji8yNYvo1K8XDMDXXK2lkwiegprur8djeKgc",
                "qta_mem":      "KlYpkZzjREFXd0GwwgLas3gJ60HB0DQfsn8sHlZ7SjE",
                "tcb":  "",
                "ak_pub":       {
                        "kty":  "RSA",
                        "n":    "v88TJ5_JSal574ODMTl2S1T2HMxZtcGcvFJa2CYQ3w7Q8otCZU4tKfXZBXQH4iZGeaBCoNFB1vinzMw5X1hFiPXMHfW-6wc1N-f1DC4Bu-WMhckdcz0qK3_Ptr9EasTs3LB5nUMffBVivm0EzW1LFIOyirY6g3NmKdjJechw9CV7XtosYT50-cgzJCwU1I7l3_qOTHq4nQ4htuuzQUXOh7nTRfFYbYRVLqF9YSFGyb5FL4Zay-2XLWRjqyX93TDN2zNaVcQa2jREAzne5Vx4zomSNe2Fjibke8ykYyvgu3ERsbhK71GAvOLt_Xrx9VpNi_oTjoEofjbh1dD9uFwO8DCk2pJm8SKlVE3b_HV9wLRNQDW13OoCMr5SDxkVIPgMCgXbpdaJRjL41d7dSX3lE45Zy6Tg7TyyAQnhbYwWz87NCnXp0OLjcejEj6xJI391Pids5yTldFfN3b_OgUKEbbNhwbIFtOfW93B15jKTnqaYMCbtsWiQxiJSZuyY6TuIeassbiLUIryzShGw6_kisnecYmzHJdQ7yAU9ZA38QAto1AyvADmfIPeaFVmqp_Z6x8aMLNndowoiwUw2UjgZdGyCDMR_A46OdsuvIec5Uiob5hfa7JIU0jhkez1fAUd8IK4AJ3s6Qd2WqQoO2891eCAvdgXG9XIwJA5cHI0YW30",
                        "e":    "AQAB"
                }
        },
        "handler":      "provisioning-output"
}
`)
)

const (
	// app scenario
	RA_SCENARIO_NO_AS = int32(iota)
	RA_SCENARIO_AS_NO_DAA
	RA_SCENARIO_AS_WITH_DAA
)

func createFiles() {
	err := ioutil.WriteFile(configFilePath, []byte(serverConfig), 0644)
	if err != nil {
		return
	}
	err1 := ioutil.WriteFile(asCertPath, []byte(ascert), 0644)
	if err1 != nil {
		return
	}
	err2 := ioutil.WriteFile(asprivPath, []byte(aspriv), 0644)
	if err2 != nil {
		return
	}
	err3 := ioutil.WriteFile(huaweiPath, []byte(huaweica), 0644)
	if err3 != nil {
		return
	}
}

func removeFiles() {
	err := os.Remove(configFilePath)
	if err != nil {
		return
	}
	err1 := os.Remove(asCertPath)
	if err1 != nil {
		return
	}
	err2 := os.Remove(asprivPath)
	if err2 != nil {
		return
	}
	err3 := os.Remove(huaweiPath)
	if err3 != nil {
		return
	}
}

func TestMakesock(t *testing.T) {
	createFiles()
	defer removeFiles()

	config.LoadConfigs()
	addr := config.GetServerPort()
	go server.StartServer(addr)
	defer server.StopServer()

	err := config.InitializeAS()
	if err != nil {
		t.Error(err)
	}

	tas, err := makesock(addr)
	if err != nil {
		t.Errorf("fail to makesock")
	}
	defer tas.conn.Close()
	defer tas.cancel()
}

func TestDoGetAKCert(t *testing.T) {
	createFiles()
	defer removeFiles()

	config.LoadConfigs()
	addr := config.GetServerPort()
	go server.StartServer(addr)
	defer server.StopServer()

	err := config.InitializeAS()
	if err != nil {
		t.Error(err)
	}

	req_1 := clientapi.GetAKCertRequest{
		Akcert:   bufferNoDAA,
		Scenario: RA_SCENARIO_AS_NO_DAA,
	}
	_, err = DoGetAKCert(addr, &req_1)
	if err != nil {
		t.Errorf("test DoGetAKCert in scenario RA_SCENARIO_AS_NO_DAA error %v", err)
	}

	req_2 := clientapi.GetAKCertRequest{
		Akcert:   bufferDAA,
		Scenario: RA_SCENARIO_AS_WITH_DAA,
	}
	_, err = DoGetAKCert(addr, &req_2)
	if err != nil {
		t.Errorf("test DoGetAKCert in scenario RA_SCENARIO_AS_WITH_DAA error %v", err)
	}

	req_3 := clientapi.GetAKCertRequest{
		Akcert:   nil,
		Scenario: RA_SCENARIO_NO_AS,
	}
	_, err = DoGetAKCert(addr, &req_3)
	if err == nil {
		t.Errorf("test DoGetAKCert in scenario RA_SCENARIO_NO_AS error %v", err)
	}
}
