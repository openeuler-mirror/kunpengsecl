/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: gwei3
Create: 2022-09-1
Description: RIM support package for ras.
*/

package rim

import (
	"crypto/x509"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
	"github.com/beevik/etree"
)

const (
	rim1 = `
<?xml version="1.0" encoding="ISO-8859-1"?>
<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" xml:lang="en-US" supplemental="false" patch="false" corpus="false" tagVersion="0" tagId="94f6b457-9ac9-4d35-9b3f-78804173b651" version="01" versionScheme="alphanumeric" name="Example.com IOTCore">
  <Entity name="Example Inc." role="softwareCreator tagCreator" regid="http://Example.com"/>
  <Link href="https://Example.com/support/ProductA/firmware/installfiles" rel="installationmedia"/>
  <Meta xmlns:rim="https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model" colloquialVersion="Firmware_2019" edition="IOT" product="ProductA" revision="r2" rim:pcURILocal="/boot/tcg/manifest/swidtag" rim:BindingSpec="IOT RIM" rim:BindingSpecVersion="1.2" rim:PlatformManufacturerId="00201234" rim:PlatformManufacturerStr="Example.com" rim:PlatformModel="ProductA" rim:FirmwareManufacturer="BIOSVendorA" rim:FirmwareManufacturerId="00213022" rim:RIMLinkHash="88f21d8e44d4271149297404df91caf207130bfa116582408abd04ede6db7f51"/>
  <Payload xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" n8060:envVarPrefix="$" n8060:envVarSuffix="" n8060:pathSeparator="/">
    <Directory name="iotBase" location="/boot/iot/">
      <File name="Example.com.iotBase.bin" version="01.00" size="15400" SHA256:hash="a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a"/>
      <File name="iotExec.bin" version="01.00" size="1024" SHA256:hash="532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"/>
    </Directory>
  </Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>5qotN58t7O9rOaExWCQVZeQ1eB0zEZYffhPL/456A3k=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Zej6BM2o36gfHVRU4GY7fYGFRQvY9+TAYKrxeiRlprniPW+fQ8V8HnTfW1o28PPUZImxqfhcTXViz0JWcC+EzJnRD/1fcxPOUN/SskmfsdMPE1cK3MarFejkQJp9xgS7TBNPYJf2IUyyTQoAYgKwWxLA7BtMSRAN3dtsCLA+XLPGCl4SPgSYUCuPNoUDXFoBN2Qq0sfSVy377r4gQqqKDC97OcQuzYWOVhmBw8UHPiy3L0AD6rKDpnKKVIaoZ47pt3903pnyE0jgohlAdbZfb6ssTmot3qV3kBR2m/EcySwyVlH5EhqRY3y/m+r08temSd/acn+zclRFS56HufYjHw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSjCCAjKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGluYTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMjA4MjUxNDU3MjJaFw0zMjA4MjUxNDU3MzJaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQKEwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6UVnyiqkQq7eIEax5mJXlfceCpFUxRGLoAgjJ8eu39T5Vdt0NSwO08Ksoo2FSQHV3ylfnbJYNtIzrVm5JGG2PMMaCugIh4GKRleCLErWh0QD3E9nNfo6GkIKVQAjdH2r1icXqLady8RV3GVUKljskbL5zNbWF+TIE6Ol0ecCMsW0Cxcq7eHP0EKBeFfpVfMXvI1cSFn7a4lKIxOW4ejpeJqK5VnE7n2MDXWY+5tb9dX9M47RItEJwmgNkMHpUQAAiJOs6NQVt1S7+3mOSEAoLdzx2/1hewb5hmdN5AEVq1yFIHs9oH+ZH1P9DSY1PHSxfZ7Z8mWzDY+cS9NeMLbGwQIDAQABo2cwZTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1UdDgQWBBR96kDk9rlya36Sug4R7xwV50i5BzAPBgNVHREECDAGhwSsFMDXMA0GCSqGSIb3DQEBCwUAA4IBAQBh7DIzYh84hEKz3pMuLv1tlZvLkRtAdbfuYrN2FZ/YxaMLcDnl4x0i8qd0d2t24v448dRQ7s2nFBiOe6N1hTc2Z54AYS5XzldqedWJUNbkWu35FXDvke6g0yJzO6n23lID+GuVjEAyHo7M0A4iSOyZXiocZwk+iJiVwITGVJxMU3KF3KwtJfAHxOyt/PfHy/1ZkdRsPDXLi2Jr9bJ6H/1fj9ilEVpBON7ULu1oVEGYjB25fuger0Kc1tD6CRaUc3gOcka4lh7xhcGEztzXUUyJXth7pHLW8Myp9BxbRr6ISvz4S2jcBpjULFZ8x1zBq/VNxJs1u2g92G1BZ4Q4qyvo</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
`
	cert1 = `
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGlu
YTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMjA4MjUx
NDU3MjJaFw0zMjA4MjUxNDU3MzJaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQK
EwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA6UVnyiqkQq7eIEax5mJXlfceCpFUxRGLoAgjJ8eu39T5Vdt0
NSwO08Ksoo2FSQHV3ylfnbJYNtIzrVm5JGG2PMMaCugIh4GKRleCLErWh0QD3E9n
Nfo6GkIKVQAjdH2r1icXqLady8RV3GVUKljskbL5zNbWF+TIE6Ol0ecCMsW0Cxcq
7eHP0EKBeFfpVfMXvI1cSFn7a4lKIxOW4ejpeJqK5VnE7n2MDXWY+5tb9dX9M47R
ItEJwmgNkMHpUQAAiJOs6NQVt1S7+3mOSEAoLdzx2/1hewb5hmdN5AEVq1yFIHs9
oH+ZH1P9DSY1PHSxfZ7Z8mWzDY+cS9NeMLbGwQIDAQABo2cwZTAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
DgQWBBR96kDk9rlya36Sug4R7xwV50i5BzAPBgNVHREECDAGhwSsFMDXMA0GCSqG
SIb3DQEBCwUAA4IBAQBh7DIzYh84hEKz3pMuLv1tlZvLkRtAdbfuYrN2FZ/YxaML
cDnl4x0i8qd0d2t24v448dRQ7s2nFBiOe6N1hTc2Z54AYS5XzldqedWJUNbkWu35
FXDvke6g0yJzO6n23lID+GuVjEAyHo7M0A4iSOyZXiocZwk+iJiVwITGVJxMU3KF
3KwtJfAHxOyt/PfHy/1ZkdRsPDXLi2Jr9bJ6H/1fj9ilEVpBON7ULu1oVEGYjB25
fuger0Kc1tD6CRaUc3gOcka4lh7xhcGEztzXUUyJXth7pHLW8Myp9BxbRr6ISvz4
S2jcBpjULFZ8x1zBq/VNxJs1u2g92G1BZ4Q4qyvo
-----END CERTIFICATE-----
`
	result1 = "ima-ng sha256:a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a /boot/iot/iotBase/Example.com.iotBase.bin\nima-ng sha256:532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25 /boot/iot/iotBase/iotExec.bin\n"

	rim2 = `
<?xml version="1.0" encoding="ISO-8859-1"?>
<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" xml:lang="en-US" supplemental="false" patch="false" corpus="false" tagVersion="0" tagId="94f6b457-9ac9-4d35-9b3f-78804173b651" version="01" versionScheme="alphanumeric" name="Example.com IOTCore">
  <Entity name="Example Inc." role="softwareCreator tagCreator" regid="http://Example.com"/>
  <Link href="https://Example.com/support/ProductA/firmware/installfiles" rel="installationmedia"/>
  <Meta xmlns:rim="https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model" colloquialVersion="Firmware_2019" edition="IOT" product="ProductA" revision="r2" rim:pcURILocal="/boot/tcg/manifest/swidtag" rim:BindingSpec="IOT RIM" rim:BindingSpecVersion="1.2" rim:PlatformManufacturerId="00201234" rim:PlatformManufacturerStr="Example.com" rim:PlatformModel="ProductA" rim:FirmwareManufacturer="BIOSVendorA" rim:FirmwareManufacturerId="00213022" rim:RIMLinkHash="88f21d8e44d4271149297404df91caf207130bfa116582408abd04ede6db7f51"/>
  <Payload xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" n8060:envVarPrefix="$" n8060:envVarSuffix="" n8060:pathSeparator="/">
    <Directory name="" location="">
      <File name="boot_aggregate" version="01.00" size="0" SHA256:hash="d41ff748c76c5a1dc10326bdad41d46ded1c0f681f1316ce76bb891666dba1dd"/>
    </Directory>
    <Directory name="modprobe.d" location="/etc/">
      <File name="tuned.conf" version="01.00" size="1024" SHA256:hash="5e8f341f27d6ae3048f41f12c310db5fa3999ec842cb39c5f547deb461a9e308"/>
    </Directory>
  </Payload>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>Xd5rzG9vxPRnKPkxL/dBzDeAWgJmgQPUGD4fqLw/R3s=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>SUAnMWNgLea8Ii5tYzMT/dNQV90b9BoUidoX/34aC92H8RIh2tvheGY2q6lZZqOxRFj3Ra5VUj/oJfALUlaIj/oWgvh3Idn2vbpZ6ihSseseEGmWyhLtzJOxsVKrluCB4xAEH1xNuW10O/S4daMmzXr2oA3qYyrDL7doU8fx+Wj3HfiL+CcudeG6kuk5KaLP4cyGwa4vpSg1R1qNFatWUs/s4m+6aoHt0Ig3KpJtvelU8dXhSA9xQlFqBb7i/8ZlVr06rWwV4s/14VGz5BKQsUKa3JZvKUHYUglvXmryrCWMmw6IOdmb9o3TrAr+YtLsPVDdUYan8PiU4b8sMoxCVg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDSjCCAjKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGluYTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMjA4MjUxNDU3MjJaFw0zMjA4MjUxNDU3MzJaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQKEwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6UVnyiqkQq7eIEax5mJXlfceCpFUxRGLoAgjJ8eu39T5Vdt0NSwO08Ksoo2FSQHV3ylfnbJYNtIzrVm5JGG2PMMaCugIh4GKRleCLErWh0QD3E9nNfo6GkIKVQAjdH2r1icXqLady8RV3GVUKljskbL5zNbWF+TIE6Ol0ecCMsW0Cxcq7eHP0EKBeFfpVfMXvI1cSFn7a4lKIxOW4ejpeJqK5VnE7n2MDXWY+5tb9dX9M47RItEJwmgNkMHpUQAAiJOs6NQVt1S7+3mOSEAoLdzx2/1hewb5hmdN5AEVq1yFIHs9oH+ZH1P9DSY1PHSxfZ7Z8mWzDY+cS9NeMLbGwQIDAQABo2cwZTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1UdDgQWBBR96kDk9rlya36Sug4R7xwV50i5BzAPBgNVHREECDAGhwSsFMDXMA0GCSqGSIb3DQEBCwUAA4IBAQBh7DIzYh84hEKz3pMuLv1tlZvLkRtAdbfuYrN2FZ/YxaMLcDnl4x0i8qd0d2t24v448dRQ7s2nFBiOe6N1hTc2Z54AYS5XzldqedWJUNbkWu35FXDvke6g0yJzO6n23lID+GuVjEAyHo7M0A4iSOyZXiocZwk+iJiVwITGVJxMU3KF3KwtJfAHxOyt/PfHy/1ZkdRsPDXLi2Jr9bJ6H/1fj9ilEVpBON7ULu1oVEGYjB25fuger0Kc1tD6CRaUc3gOcka4lh7xhcGEztzXUUyJXth7pHLW8Myp9BxbRr6ISvz4S2jcBpjULFZ8x1zBq/VNxJs1u2g92G1BZ4Q4qyvo</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>
`
	cert2 = `
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MQ4wDAYDVQQGEwVDaGlu
YTEQMA4GA1UEChMHQ29tcGFueTEQMA4GA1UEAxMHUm9vdCBDQTAeFw0yMjA4MjUx
NDU3MjJaFw0zMjA4MjUxNDU3MzJaMDQxDjAMBgNVBAYTBUNoaW5hMRAwDgYDVQQK
EwdDb21wYW55MRAwDgYDVQQDEwdSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA6UVnyiqkQq7eIEax5mJXlfceCpFUxRGLoAgjJ8eu39T5Vdt0
NSwO08Ksoo2FSQHV3ylfnbJYNtIzrVm5JGG2PMMaCugIh4GKRleCLErWh0QD3E9n
Nfo6GkIKVQAjdH2r1icXqLady8RV3GVUKljskbL5zNbWF+TIE6Ol0ecCMsW0Cxcq
7eHP0EKBeFfpVfMXvI1cSFn7a4lKIxOW4ejpeJqK5VnE7n2MDXWY+5tb9dX9M47R
ItEJwmgNkMHpUQAAiJOs6NQVt1S7+3mOSEAoLdzx2/1hewb5hmdN5AEVq1yFIHs9
oH+ZH1P9DSY1PHSxfZ7Z8mWzDY+cS9NeMLbGwQIDAQABo2cwZTAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0lBAgwBgYEVR0lADASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1Ud
DgQWBBR96kDk9rlya36Sug4R7xwV50i5BzAPBgNVHREECDAGhwSsFMDXMA0GCSqG
SIb3DQEBCwUAA4IBAQBh7DIzYh84hEKz3pMuLv1tlZvLkRtAdbfuYrN2FZ/YxaML
cDnl4x0i8qd0d2t24v448dRQ7s2nFBiOe6N1hTc2Z54AYS5XzldqedWJUNbkWu35
FXDvke6g0yJzO6n23lID+GuVjEAyHo7M0A4iSOyZXiocZwk+iJiVwITGVJxMU3KF
3KwtJfAHxOyt/PfHy/1ZkdRsPDXLi2Jr9bJ6H/1fj9ilEVpBON7ULu1oVEGYjB25
fuger0Kc1tD6CRaUc3gOcka4lh7xhcGEztzXUUyJXth7pHLW8Myp9BxbRr6ISvz4
S2jcBpjULFZ8x1zBq/VNxJs1u2g92G1BZ4Q4qyvo
-----END CERTIFICATE-----
`
	result2 = "ima-ng sha256:d41ff748c76c5a1dc10326bdad41d46ded1c0f681f1316ce76bb891666dba1dd boot_aggregate\nima-ng sha256:5e8f341f27d6ae3048f41f12c310db5fa3999ec842cb39c5f547deb461a9e308 /etc/modprobe.d/tuned.conf\n"

	validatedRim3 = `
<?xml version="1.0" encoding="ISO-8859-1"?>
<SoftwareIdentity xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:n8060="http://csrc.nist.gov/ns/swid/2015-extensions/1.0" xml:lang="en-US" supplemental="false" patch="false" corpus="false" tagVersion="0" tagId="94f6b457-9ac9-4d35-9b3f-78804173b651" version="01" versionScheme="alphanumeric" name="Example.com IOTCore">
  <Entity name="Example Inc." role="softwareCreator tagCreator" regid="http://Example.com"/>
  <Link href="https://Example.com/support/ProductA/firmware/installfiles" rel="installationmedia"/>
  <Meta xmlns:rim="https://trustedcomputinggroup.org/wp-content/uploads/TCG_RIM_Model" colloquialVersion="Firmware_2019" edition="IOT" product="ProductA" revision="r2" rim:pcURILocal="/boot/tcg/manifest/swidtag" rim:BindingSpec="IOT RIM" rim:BindingSpecVersion="1.2" rim:PlatformManufacturerId="00201234" rim:PlatformManufacturerStr="Example.com" rim:PlatformModel="ProductA" rim:FirmwareManufacturer="BIOSVendorA" rim:FirmwareManufacturerId="00213022" rim:RIMLinkHash="88f21d8e44d4271149297404df91caf207130bfa116582408abd04ede6db7f51"/>
  <Payload xmlns:SHA256="http://www.w3.org/2001/04/xmlenc#sha256" n8060:envVarPrefix="$" n8060:envVarSuffix="" n8060:pathSeparator="/">
    <Directory name="" location="">
      <File name="boot_aggregate" version="01.00" size="0" SHA256:hash="532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"/>
    </Directory>
    <Directory name="" location="/">
      <File name="iotExec.bin" version="01.00" size="1024" SHA256:hash="532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"/>
    </Directory>
    <Directory name="iotBase" location="/boot/iot/">
      <File name="Example.com.iotBase.bin" version="01.00" size="15400" SHA256:hash="a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a"/>
      <File name="iotExec.bin" version="01.00" size="1024" SHA256:hash="532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"/>
    </Directory>
  </Payload>
</SoftwareIdentity>
`
	result3 = "ima-ng sha256:532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25 boot_aggregate\nima-ng sha256:532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25 /iotExec.bin\nima-ng sha256:a314fc2dc663ae7a6b6bc6787594057396e6b3f569cd50fd5ddb4d1bbafd2b6a /boot/iot/iotBase/Example.com.iotBase.bin\nima-ng sha256:532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25 /boot/iot/iotBase/iotExec.bin\n"
)

var (
	testCases1 = []struct {
		rim    []byte
		cert   *x509.Certificate
		dAlg   string
		result string
	}{
		{[]byte(rim1), decodeCert(cert1), typdefs.Sha256AlgStr, result1},
		{[]byte(rim2), decodeCert(cert2), typdefs.Sha256AlgStr, result2},
	}
	testCases2 = []struct {
		rim    *etree.Document
		dAlg   string
		result string
	}{
		{rim2Doc(validatedRim3), typdefs.Sha256AlgStr, result3},
	}
)

func decodeCert(pemCert string) (c *x509.Certificate) {
	c, _, err := cryptotools.DecodeKeyCertFromPEM([]byte(pemCert))
	if err != nil {
		return nil
	}

	return c
}

func rim2Doc(rim string) (doc *etree.Document) {
	doc = etree.NewDocument()
	err := doc.ReadFromBytes([]byte(rim))
	if err != nil {
		return nil
	}

	return doc
}

func TestParseRIM(t *testing.T) {
	for i := 0; i < len(testCases1); i++ {
		ima, err := ParseRIM(testCases1[i].rim, testCases1[i].cert, testCases1[i].dAlg)
		if ima != testCases1[i].result {
			t.Errorf("error at case %d\n", i)
			if err != nil {
				t.Errorf("error info: %s\n", err.Error())
			}
			t.Errorf("expecting: \n%s\n", testCases1[i].result)
			t.Errorf("real     : \n%s\n", ima)
		}
	}
}

func TestRim2ima(t *testing.T) {
	for i := 0; i < len(testCases2); i++ {
		ima, err := rim2ima(testCases2[i].rim, testCases2[i].dAlg)
		if ima != testCases2[i].result {
			t.Errorf("error at case %d\n", i)
			if err != nil {
				t.Errorf("error info: %s\n", err.Error())
			}
			t.Errorf("expecting: \n%s\n", testCases2[i].result)
			t.Errorf("real     : \n%s\n", ima)
		}
	}
}
