/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun/lixinda
Create: 2021-11-12
Description: Implement a privacy CA to sign identity key(AIK).
	1. 2022-01-17	change the ras/pca package to common/cryptotools.
*/

// cryptotools package provides the common crypto and format functions for use.
package cryptotools

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"sync/atomic"
	"time"
)

const (
	// algorithms define from tpm2
	// AlgNull means nul mode
	AlgNull = 0x0000
	// AlgRSA means RSA algorithm
	AlgRSA = 0x0001
	// AlgAES means AES algorithm
	AlgAES = 0x0006
	// AlgOAEP means OAEP algorithm
	AlgOAEP = 0x0017
	// AlgCTR means CTR mode
	AlgCTR = 0x0040
	// AlgOFB means OFB mode
	AlgOFB = 0x0041
	// AlgCBC means CBC mode
	AlgCBC = 0x0042
	// AlgCFB means CFB mode
	AlgCFB = 0x0043
	// KEYSIZE means the size of key
	KEYSIZE = 16

	// Encrypt_Alg means AES128 encryption algorithm with CBC mode
	Encrypt_Alg = "AES128-CBC"
	// AesKeySize means the size of AES algorithm key
	AesKeySize = 16
	// RsaKeySize means the size of RSA algorithm key
	RsaKeySize     = 2048
	headPrivKey    = "PRIVATE KEY"
	headPubKey     = "PUBLIC KEY"
	headRsaPrivKey = "RSA PRIVATE KEY"
	headRsaPubKey  = "RSA PUBLIC KEY"
	modKey         = 0600
	headCert       = "CERTIFICATE"
	modCert        = 0644
)

type (
	IKCertChallenge struct {
		EncryptedCert []byte
		SymKeyParams  SymKeyParams
	}

	// SymKeyParams means symmetric encryption key parameter
	SymKeyParams struct {
		CredBlob        []byte
		EncryptedSecret []byte
		// the algorithm & scheme used to encrypt the IK Cert
		EncryptAlg string
		// the parameter required by the encrypt algorithm to decrypt the IK Cert
		// if encryptAlg == "AES128-CBC" then it is the IV used to encrypt IK Cert
		// together with the key recovered from credBlob & encryptedSecret
		EncryptParam []byte
	}

	// TPMAsymKeyParams means asymmetric encryption key parameter in TPM
	TPMAsymKeyParams struct {
		TPMAsymAlgorithm string
		TPMEncscheme     string
	}
)

var (
	serialNumber int64 = 1

	// error definition
	// ErrEncodeDER means encoding DER []byte failed
	ErrEncodeDER = errors.New("failed to encode DER []byte")
	// ErrEncodePEM means encoding PEM information failed
	ErrEncodePEM = errors.New("failed to encode PEM information")
	// ErrDecodePEM means decoding PEM information failed
	ErrDecodePEM = errors.New("failed to decode PEM information")
	// ErrParseKey means parsing key failed
	ErrParseKey = errors.New("failed to parse the key")
	// ErrWrongParams means input parameter is wrong
	ErrWrongParams = errors.New("wrong input parameter")
)

// GetRandomBytes gets random bytes
func GetRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func pkcs7Pad(c []byte, n int) []byte {
	pad := n - len(c)%n
	pt := bytes.Repeat([]byte{byte(pad)}, pad)
	return append(c, pt...)
}

func pkcs7Unpad(d []byte) []byte {
	n := len(d)
	pad := int(d[n-1])
	return d[:n-pad]
}

func aesCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	n := cb.BlockSize()
	d := pkcs7Pad(plaintext, n)
	bm := cipher.NewCBCEncrypter(cb, iv)
	ciphertext := make([]byte, len(d))
	bm.CryptBlocks(ciphertext, d)
	return ciphertext, nil
}

func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	bm := cipher.NewCBCDecrypter(cb, iv)
	plaintext := make([]byte, len(ciphertext))
	bm.CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext), nil
}

func aesCFBEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	st := cipher.NewCFBEncrypter(cb, iv)
	ciphertext := make([]byte, len(plaintext))
	st.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

func aesCFBDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	st := cipher.NewCFBDecrypter(cb, iv)
	plaintext := make([]byte, len(ciphertext))
	st.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func aesOFBEncDec(key, iv, in []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	st := cipher.NewOFB(cb, iv)
	out := make([]byte, len(in))
	st.XORKeyStream(out, in)
	return out, nil
}

func aesCTREncDec(key, iv, in []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if iv == nil {
		iv = bytes.Repeat([]byte("\x00"), cb.BlockSize())
	}
	st := cipher.NewCTR(cb, iv)
	out := make([]byte, len(in))
	st.XORKeyStream(out, in)
	return out, nil
}

// SymmetricEncrypt uses key/iv to encrypt the plaintext with symmetric algorithm/mode.
func SymmetricEncrypt(alg, mod uint16, key, iv, plaintext []byte) ([]byte, error) {
	switch alg {
	case AlgAES:
		switch mod {
		case AlgCBC:
			return aesCBCEncrypt(key, iv, plaintext)
		case AlgCFB:
			return aesCFBEncrypt(key, iv, plaintext)
		case AlgOFB:
			return aesOFBEncDec(key, iv, plaintext)
		case AlgCTR:
			return aesCTREncDec(key, iv, plaintext)
		}
	}
	return []byte{}, ErrWrongParams
}

// SymmetricDecrypt uses key/iv to decrypt the ciphertext with symmetric algorithm/mode.
func SymmetricDecrypt(alg, mod uint16, key, iv, ciphertext []byte) ([]byte, error) {
	switch alg {
	case AlgAES:
		switch mod {
		case AlgCBC:
			return aesCBCDecrypt(key, iv, ciphertext)
		case AlgCFB:
			return aesCFBDecrypt(key, iv, ciphertext)
		case AlgOFB:
			return aesOFBEncDec(key, iv, ciphertext)
		case AlgCTR:
			return aesCTREncDec(key, iv, ciphertext)
		}
	}
	return []byte{}, ErrWrongParams
}

// AsymmetricEncrypt encrypts a byte array by public key and label using RSA
func AsymmetricEncrypt(alg, mod uint16, pubKey crypto.PublicKey, plaintext, label []byte) ([]byte, error) {
	switch alg {
	case AlgRSA:
		switch mod {
		case AlgOAEP:
			return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey.(*rsa.PublicKey), plaintext, label)
		default:
			return rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), plaintext)
		}
	}
	return []byte{}, ErrWrongParams
}

// AsymmetricDecrypt decrypts a byte array by private key and label using RSA
func AsymmetricDecrypt(alg, mod uint16, priKey crypto.PrivateKey, ciphertext, label []byte) ([]byte, error) {
	switch alg {
	case AlgRSA:
		switch mod {
		case AlgOAEP:
			return rsa.DecryptOAEP(sha256.New(), rand.Reader, priKey.(*rsa.PrivateKey), ciphertext, label)
		default:
			return rsa.DecryptPKCS1v15(rand.Reader, priKey.(*rsa.PrivateKey), ciphertext)
		}
	}
	return []byte{}, ErrWrongParams
}

/*
Trusted Platform Module Library
Part 1: Architecture
Family "2.0"
Level 00 Revision 01.59
November 8, 2019
Published

	Contact admin@trustedcomputinggroup.org
	TCG Published
	Copyright(c) TCG 2006-2020

Page 43
11.4.10 Key Derivation Function
11.4.10.1 Introduction
The TPM uses a hash-based function to generate keys for multiple purposes. This
specification uses two different schemes: one for ECDH and one for all other
uses of a KDF.
The ECDH KDF is from SP800-56A. The Counter mode KDF, from SP800-108, uses HMAC
as the pseudo-random function (PRF). It is refered to in the specification as
KDFa().

11.4.10.2 KDFa()
With the exception of ECDH, KDFa() is used in all cases where a KDF is required.
KDFa() uses Counter mode from SP800-108, with HMAC as the PRF.
As defined in SP800-108, the inner loop for building the key stream is:

	K(i) := HMAC(K, [i] || Label || 00 || Context || [L])           (6)

where

	K(i)    the i(th) iteration of the KDF inner loop
	HMAC()  the HMAC algorithm using an approved hash algorithm
	K       the secret key material
	[i]     a 32-bit counter that starts at 1 and increments on each iteration
	Label   a octet stream indicating the use of the key produced by this KDF
	00      Added only if Label is not present or if the last octect of Label is not zero
	Context a binary string containing information relating to the derived keying material
	[L]     a 32-bit value indicating the number of bits to be returned from the KDF

NOTE1
Equation (6) is not KDFa(). KDFa() is the function call defined below.

As shown in equation (6), there is an octet of zero that separates Label from
Context. In SP800-108, Label is a sequence of octets that may or may not have
a final octet that is zero. If Label is not present, a zero octet is added.
If Label is present and the last octet is not zero, a zero octet is added.
After each iteration, the HMAC digest data is concatenated to the previously
produced value until the size of the concatenated string is at least as large
as the requested value. The string is then truncated to the desired size (which
causes the loss of some of the most recently added bits), and the value is
returned.

When this specification calls for use of this KDF, it uses a function reference
to KDFa(). The function prototype is:

	KDFa(hashAlg, key, label, contextU, contextV, bits)             (7)

where

	hashAlg  a TPM_ALG_ID to be used in the HMAC in the KDF
	key      a variable-sized value used as K
	label    a variable-sized octet stream used as Label
	contextU a variable-sized value concatenated with contextV to create the
	         Context parameter used in equation (6) above
	contextV a variable-sized value concatenated with contextU to create the
	         Context parameter used in equation (6) above
	bits     a 32-bit value used as [L], and is the number of bits returned
	         by the function

The values of contextU and contextV are passed as sized buffers and only the
buffer data is used to construct the Context parameter used in equation (6)
above. The size fields of contextU and contextV are not included in the
computation. That is:

	Context := contextU.buffer || contextV.buffer                   (8)

The 32-bit value of bits is in TPM canonical form, with the least significant
bits of the value in the highest numbered octet.

The implied return from this function is a sequence of octets with a length
equal to (bits+7)/8. If bits is not an even multiple of 8, then the returned
value occupies the least significant bits of the returned octet array, and
the additional, high-order bits in the 0(th) octet are CLEAR.
The unused bits of the most significant octet(MSO) are masked off and not shifted.

EXAMPLE
If KDFa() were used to produce a 521-bit ECC private key, the returned value
would occupy 66 octets, with the upper 7 bits of the octet at offset zero
set to 0.
*/
func KDFa(alg crypto.Hash, key []byte, label string, contextU, contextV []byte, bits int) ([]byte, error) {
	bufLen := (bits + 7) / 8
	if bufLen > math.MaxInt16 {
		return []byte{}, ErrWrongParams
	}
	buf := []byte{}
	h := hmac.New(alg.New, key)
	for i := 1; len(buf) < bufLen; i++ {
		h.Reset()
		err := binary.Write(h, binary.BigEndian, uint32(i))
		if err != nil {
			return nil, errors.New("failed to write")
		}
		if len(label) > 0 {
			_, err1 := h.Write([]byte(label))
			if err1 != nil {
				return nil, errors.New("failed to write")
			}
			_, err2 := h.Write([]byte{0})
			if err2 != nil {
				return nil, errors.New("failed to write")
			}
		}
		if len(contextU) > 0 {
			_, err3 := h.Write(contextU)
			if err3 != nil {
				return nil, errors.New("failed to write")
			}
		}
		if len(contextV) > 0 {
			_, err4 := h.Write(contextV)
			if err4 != nil {
				return nil, errors.New("failed to write")
			}
		}
		err5 := binary.Write(h, binary.BigEndian, uint32(bits))
		if err5 != nil {
			return nil, errors.New("failed to write")
		}
		buf = h.Sum(buf)
	}
	buf = buf[:bufLen]
	mask := uint8(bits % 8)
	if mask > 0 {
		buf[0] &= (1 << mask) - 1
	}
	return buf, nil
}

/*
---
Trusted Platform Module Library
Part 1: Architecture
Family "2.0"
Level 00 Revision 01.59
November 8, 2019
Published

	Contact admin@trustedcomputinggroup.org
	TCG Published
	Copyright(c) TCG 2006-2020

Page 161
24 Credential Protection
24.1 Introduction
The TPM supports a privacy preserving protocol for distributing credentials for
keys on a TPM. The process allows a credential provider to assign a credential
to a TPM object, such that the credential provider cannot prove that the object
is resident on a particular TPM, but the credential is not available unless the
object is resident on a device that the credential provider believes is an
authentic TPM.

24.2 Protocol
The initiator of the credential process will provide, to a credential provider,
the public area of a TPM object for which a credential is desired along with
the credentials for a TPM key (usually an EK). The credential provider will
inspect the credentials of the "EK" and the properties indicated in the public
area to determine if the object should receive a credential. If so, the
credential provider will issue a credential for the public area.
The credential provider may require that the credential only be useable if the
public area is a valid object on the same TPM as the "EK". To ensure this, the
credential provider encrypts a challenge and then "wraps" the challenge
encryption key with the public key of the "EK".
NOTE:

	"EK" is used to indicate that an EK is typically used for this process but

any storage key may be used. It is up to the credential provider to decide
what is acceptable for an "EK".

The encrypted challenge and the wrapped encryption key are then delivered to
the initiator. The initiator can decrypt the challenge by loading the "EK"
and the object onto the TPM and asking the TPM to return the challenge. The
TPM will decrypt the challenge using the private "EK" and validate that the
credentialed object (public and private) is loaded on the TPM. If so, the
TPM has validated that the properties of the object match the properties
required by the credential provider and the TPM will return the challenge.
This process preserves privacy by allowing TPM TPM objects to have credentials
from the credential provider that are not tied to a specific TPM. If the
object is a signing key, that key may be used to sign attestations, and the
credential can assert that the signing key is on a valid TPM without disclosing
the exact TPM.
A second property of this protocol is that it prevents the credential provider
from proving anything about the object for which it provided the credential.
The credential provider could have produced the credential with no information
from the TPM as the TPM did not need to provide a proof-of-possession of any
private key in order for the credential provider to create the credential.
The credential provider can know that the credential for the object could not
be in use unless the object was on the same TPM as the "EK", but the credential
provider cannot prove it.

24.3 Protection of Credential
The credential blob (which typically contains the information used to decrypt
the challenge) from the credential provider contains a value that is returned
by the TPM if the TPM2_ActivateCredential() is successful. The value may be
anything that the credential provider wants to place in the credential blob
but is expected to be simply a large random number.
The credential provider protects the credential value (CV) with an integrity
HMAC and encryption in much the same way as a credential blob. The difference
is, when SEED is generated, the label is "IDENTITY" instead of "DUPLICATE".

24.4 Symmetric Encrypt
A SEED is derived from values that are protected by the asymmetric algorithm
of the "EK". The methods of generating the SEED are determined by the
asymmetric algorithm of the "EK" and are described in an annex to this TPM 2.0
Part 1. In the process of creating SEED, the label is required to be "INTEGRITY".
NOTE:

	If a duplication blob is given to the TPM, its HMAC key will be wrong and

the HMAC check will fail.

Given a value for SEED, a key is created by:

	symKey := KDFa(ekNameAlg, SEED, "STORAGE", name, NULL, bits)    (44)

where

	ekNameAlg  the nameAlg of the key serving as the "EK"
	SEED       the symmetric seed value produced using methods specific to
	           the type of asymmetric algorithms of the "EK"
	"STORAGE"  a value used to differentiate the uses of the KDF
	name       the Name of the object associated with the credential
	bits       the number of bits required for the symmetric key

The symKey is used to encrypt the CV. The IV is set to 0.

	encIdentity := CFB(symKey, 0, CV)                               (45)

where

	CFB        symmetric encryption in CFB mode using the symmetric
	           algorithm of the key serving as "EK"
	symKey     symmetric key from (44)
	CV         the credential value (a TPM2B_DIGEST)

24.5 HMAC
A final HMAC operation is applied to the encIdentity value. This is to ensure
that the TPM can properly associate the credential with a loaded object and
to prevent misuse of or tampering with the CV.
The HMAC key (HMACkey) for the integrity is computed by:

	HMACkey := KDFa(ekNameAlg, SEED, "INTEGRITY", NULL, NULL, bits) (46)

where

	ekNameAlg    the nameAlg of the target "EK"
	SEED         the symmetric seed value used in (44); produced using
	             methods specific to the type of asymmetric algorithms
	             of the "EK"
	"INTEGRITY"  a value used to differentiate the uses of the KDF
	bits         the number of bits in the digest produced by ekNameAlg

NOTE:

	Even though the same value for label is used for each integrit HMAC, SEED

is created in a manner that is unique to the application. Since SEED is
unique to the application, the HMAC is unique to the application.

HMACkey is then used in the integrity computation.

	identityHMAC := HMAC(HMACkey, encIdentity || Name)              (47)

where

	HMAC         the HMAC function using nameAlg of the "EK"
	HMACkey      a value derived from the "EK" symmetric protection
	             value according to equation (46)
	encIdentity  symmetrically encrypted sensitive area produced in (45)
	Name         the Name of the object being protected

The integrity structure is constructed by placing the identityHMAC (size and
hash) in the buffer ahead of the encIdentity.

24.6 Summary of Protection Process
 1. Marshal the CV(credential value) into a TPM2B_DIGEST
 2. Using methods of the asymmetric "EK", create a SEED value
 3. Create a symmetric key for encryption:
    symKey := KDFa(ekNameAlg, SEED, "STORAGE", Name, NULL, bits)
 4. Create encIdentity by encryption the CV
    encIdentity := CFB(symKey, 0, CV)
 5. Compute the HMACkey
    HMACkey := KDFa(ekNameAlg, SEED, "INTEGRITY", NULL, NULL, bits)
 6. Compute the HMAC over the encIdentity from step 4
    outerHMAC := HMAC(HMACkey, encIdentity || Name)

---
Also reference
Trusted Platform Module Library
Part 3: Commands
Family "2.0"
Level 00 Revision 01.59
November 8, 2019
Page 72
12.6 TPM2_MakeCredential

---
Another book: <<A Practical Guide to TPM2.0>>

	Using the Trusted Platform Module in the New Age of Security
		Will Arthur and David Challener
		With Kenneth Goldman

FIGURE 9-1. Activating a Credential (CHAPTER 9/Page 109)

	Credential Provider(Privacy CA)                 TPM
	                    Public Key, TPM Encryption Key Certificate
	                                    <<===

1.         Validate Certificate chain <=
2.                 Examine Public Key <=
3.                Generate Credential <=
4.Generate Secret and wrap Credential <=
 5. Generate Seed, encrypt Seed <=
    with TPM Encryption Key
 6. Use Seed in KDF (with Name) to <=
    derive HMAC key and Symmetric
    Key, Wrap Secret in Symmetric
    Key and protect with HMAC Key
    Credential wrapped by Secret,
    Secret wrapped by Symmetric Key derived from Seed,
    Seed encrypted by TPM Encryption Key.
    ===>>
    1.=> Decrypt Seed using TPM Encryption Key.
    2.=> Compute Name.
    3.=> Use Seed KDF (with Name) to derive
    HMAC Key and Symmetric Key.
    4.=> Use Symmetric Key to unwrap Secret.
    5.=> Use Secret to unwrap Credential.

The following happens at the credential provider: (Page 110)
1. The credential provider receives the Key's public area and a certificate for
an Encryption Key. The Encryption Key is typically a primary key in the
endorsement hierarchy, and its certificate is issued by the TPM and/or platform
manufacturer.
2. The credential provider walks the Encryption Key certificate chain back to
the issuer's root. Typically, the provider verifies that the Encryption Key is
fixed to a known compliant hardware TPM.
3. The provider examines the Key's public area and decides whether to issue a
certificate, and what the certificate should say. In a typical case, the
provider issues a certificate for a restricted Key that is fixed to the TPM.
4. The requester may have tried to alter the Key's public area attributes.
This attack won't be successful. See step 5 in the process that occurs at the
TPM.
5. The provider generates a credential for the Key.
6. The provider generates a Secret that is used to protect the credential.
Typically, this is a symmetric encryption key, but it can be a secret used to
generate encryption and integrity keys. The format and use of this secret aren't
mandated by the TCG.
7. The provider generates a 'Seed' to a key derivation function(KDF). If the
Encryption Key is an RSA key, the Seed is simply a random number, because an
RSA key can directly encrypt and decrypt. If the Decryption Key is an elliptic
curve cryptography(ECC) key, a more complex procedure using a Diffie-Hellman
protocol is required.
8. This Seed is encrypted by the Encryption Key public key. It can later only
be decrypted by the TPM.
9. The Seed is used in a TCG-specified KDF to generate a symmetric encryption
key and an HMAC key. The symmetric key is used to encrypt the Secret, and the
HMAC key provides integrity. Subtle but important is that the KDF also uses
the key's Name. You'll see why later.
10. The encrypted Secret and its integrity value are sent to the TPM in a
credential blob. The encrypted Seed is sent as well.

If you follow all this, you have the following:
#) A credential protected by a Secret
#) A Secret encrypted by a key derived from a Seed and the key's Name
#) A Seed encrypted by a TPM Encryption Key

These thins happen at the TPM:
1. The encrypted Seed is applied against the TPM Encryption Key, and the Seed
is recovered. The Seed remains inside the TPM.
2. The TPM computes the loaded key's Name.
3. The Name and the Seed are combined using the same TCG KDF to produce a
symmetric encryption key and an HMAC key.
4. The two keys are applied to the protected Secret, checking its integrity
and decrypting it.
5. This is where an attack on the key's public area attributes is detected.
If the attacker presents a key to the credential provider that is different
from the key loaded in the TPM, the Name will differ, and thus the symmetric
and HMAC keys will differ, and this step will fail.
6. The TPM returns the Secret.

Outside the TPM, the Secret is applied to the credential in some agreed upon
way. This can be as simple as using the Secret as a symmetric decryption key
to decrypt the credential. This protocol assures the credential provider that
the credential can only be recovered if:
#) The TPM has the private key associated with the Encryption key certificate.
#) The TPM has a key identical to the one presented to the credential provider.
The privacy administrator should control the use of the Endorsement Key, both
as a signing key and in the activate-credential protocol, and thus control its
correlation to another TPM key.

Other Privacy Considerations
The TPM owner can clear the storage hierarchy, changing the storage primary
seed and effectively erasing all storage hierarchy keys.
The platform owner controls the endorsement hierarchy. The platform owner
typically doesn't allow the endorsement primary seed to be changed, because
this would render the existing TPM certificates useless, with no way to recover.
The user can create other primary keys in the endorsement hierarchy using a
random number in the template. The user can erase these keys by flushing the
key from the TPM, deleting external copies, and forgetting the random number.
However, these keys do not have a manufacturer certificate.
When keys are used to sign(attest to) certain data, the attestation response
structure contains what are possibly privacy-sensitive fields: resetCount(the
number of times the TPM has been reset), restartCount(the number of times the
TPM has been restarted or resumed), and the firmware version. Although these
values don't map directly to a TPM, they can aid in correlation.
To avoid this issue, the values are obfuscated when the signing key isn't in
the endorsement or platform hierarchy. The obfuscation is consistent when
using the same key so the receiver can detect a change in the values while
not seeing the actual values.
*/
func MakeCredential(ekPubKey crypto.PublicKey, credential, name []byte) ([]byte, []byte, error) {
	if len(credential) == 0 || len(name) == 0 || len(credential) > crypto.SHA256.Size() {
		return nil, nil, ErrWrongParams
	}
	// step 1, size(uint16) + content
	plaintext := new(bytes.Buffer)
	err := binary.Write(plaintext, binary.BigEndian, uint16(len(credential)))
	if err != nil {
		return nil, nil, errors.New("failed to write")
	}
	err1 := binary.Write(plaintext, binary.BigEndian, credential)
	if err1 != nil {
		return nil, nil, errors.New("failed to write")
	}
	// step 2,
	seed, err2 := GetRandomBytes(KEYSIZE)
	if err2 != nil {
		return nil, nil, errors.New("failed to get random bytes")
	}
	encSeed, err3 := AsymmetricEncrypt(AlgRSA, AlgOAEP, ekPubKey, seed, []byte("IDENTITY\x00"))
	if err3 != nil {
		return nil, nil, errors.New("failed to AsymmetricEncrypt")
	}
	// step 3
	symKey, err4 := KDFa(crypto.SHA256, seed, "STORAGE", name, nil, KEYSIZE*8)
	if err4 != nil {
		return nil, nil, errors.New("failed to KDFa")
	}
	// step 4
	encIdentity, err5 := SymmetricEncrypt(AlgAES, AlgCFB, symKey, nil, plaintext.Bytes())
	if err5 != nil {
		return nil, nil, errors.New("failed to SymmetricEncrypt")
	}
	// step 5
	hmacKey, err6 := KDFa(crypto.SHA256, seed, "INTEGRITY", nil, nil, crypto.SHA256.Size()*8)
	if err6 != nil {
		return nil, nil, errors.New("failed to KDFa")
	}
	// step 6
	integrityBuf := new(bytes.Buffer)
	err7 := binary.Write(integrityBuf, binary.BigEndian, encIdentity)
	if err7 != nil {
		return nil, nil, errors.New("failed to write")
	}
	err8 := binary.Write(integrityBuf, binary.BigEndian, name)
	if err8 != nil {
		return nil, nil, errors.New("failed to write")
	}
	mac := hmac.New(sha256.New, hmacKey)
	_, err9 := mac.Write(integrityBuf.Bytes())
	if err9 != nil {
		return nil, nil, errors.New("failed to write")
	}
	integrity := mac.Sum(nil)
	// last step: prepare output
	allBlob := new(bytes.Buffer)
	err10 := binary.Write(allBlob, binary.BigEndian, uint16(len(integrity)))
	if err10 != nil {
		return nil, nil, errors.New("failed to write")
	}
	err11 := binary.Write(allBlob, binary.BigEndian, integrity)
	if err11 != nil {
		return nil, nil, errors.New("failed to write")
	}
	err12 := binary.Write(allBlob, binary.BigEndian, encIdentity)
	if err12 != nil {
		return nil, nil, errors.New("failed to write")
	}
	return allBlob.Bytes(), encSeed, nil
}

// EncodeKeyPubPartToDER encodes the private key public part into a der []byte.
func EncodeKeyPubPartToDER(key crypto.PrivateKey) ([]byte, error) {
	var err error
	var derData []byte
	switch priv := key.(type) {
	case *rsa.PrivateKey:
		derData, err = x509.MarshalPKIXPublicKey(priv.Public())
		if err != nil {
			return nil, err
		}
		return derData, nil
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	}
	return derData, ErrEncodeDER
}

// EncodePublicKeyToPEM encodes the public key to a pem []byte.
func EncodePublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	var pemData []byte
	switch pub.(type) {
	case *rsa.PublicKey:
		derBuf, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}
		pemData = pem.EncodeToMemory(
			&pem.Block{
				Type:  headPubKey,
				Bytes: derBuf,
			},
		)
		return pemData, nil
	case *ecdsa.PublicKey:
	case ed25519.PublicKey:
	}
	return nil, ErrEncodePEM
}

// EncodePublicKeyToFile encodes the public key to a file as pem format.
func EncodePublicKeyToFile(pub crypto.PublicKey, fileName string) error {
	data, err := EncodePublicKeyToPEM(pub)
	if err != nil {
		return errors.New("failed to encode public key to pem")
	}
	return ioutil.WriteFile(fileName, data, modKey)
}

// EncodePrivateKeyToPEM encodes the private key to a pem []byte.
func EncodePrivateKeyToPEM(priv crypto.PrivateKey) ([]byte, error) {
	var pemData []byte
	switch priv.(type) {
	case *rsa.PrivateKey:
		derBuf, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pemData = pem.EncodeToMemory(
			&pem.Block{
				Type:  headPrivKey,
				Bytes: derBuf,
			},
		)
		return pemData, nil
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
	}
	return nil, ErrEncodePEM
}

// EncodePrivateKeyToFile encodes the private key to a file as pem format.
func EncodePrivateKeyToFile(priv crypto.PrivateKey, fileName string) error {
	data, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		return errors.New("failed to encode private key to pem")
	}
	return ioutil.WriteFile(fileName, data, modKey)
}

// EncodeKeyCertToPEM encodes the der form key certificate to a pem []byte.
func EncodeKeyCertToPEM(certDer []byte) ([]byte, error) {
	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  headCert,
			Bytes: certDer,
		},
	)
	return pemData, nil
}

// EncodeKeyCertToFile encodes the der form key certificate to a pem file.
func EncodeKeyCertToFile(certDer []byte, fileName string) error {
	data, err := EncodeKeyCertToPEM(certDer)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fileName, data, modCert)
}

// DecodePublicKeyFromPEM decodes a pem []byte to get the public key.
func DecodePublicKeyFromPEM(pemData []byte) (crypto.PublicKey, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != headPubKey {
		return nil, nil, ErrDecodePEM
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, ErrParseKey
	}
	return pub, block.Bytes, nil
}

// DecodePublicKeyFromFile decodes a pem file to get the public key.
func DecodePublicKeyFromFile(fileName string) (crypto.PublicKey, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodePublicKeyFromPEM(data)
}

// DecodePrivateKeyFromPEM decodes a pem []byte to get the private key.
func DecodePrivateKeyFromPEM(pemData []byte) (crypto.PrivateKey, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != headPrivKey {
		return nil, nil, ErrDecodePEM
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, ErrParseKey
	}
	return priv, block.Bytes, nil
}

// DecodePrivateKeyFromFile decodes a pem file to get the private key.
func DecodePrivateKeyFromFile(fileName string) (crypto.PrivateKey, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodePrivateKeyFromPEM(data)
}

// DecodeKeyCertFromPEM decodes the key certificate from a pem format []byte.
func DecodeKeyCertFromPEM(pemData []byte) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil, ErrDecodePEM
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, ErrParseKey
	}
	return cert, block.Bytes, nil
}

// DecodeKeyCertFromFile decodes a pem file to get the key certificate.
func DecodeKeyCertFromFile(fileName string) (*x509.Certificate, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	return DecodeKeyCertFromPEM(data)
}

// DecodeKeyCertFromNVFile decode the cert from NVRAM's file
func DecodeKeyCertFromNVFile(fileName string) (*x509.Certificate, []byte, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, nil, err
	}
	// remove excess 0
	for i := range data {
		if data[i] == 0 && data[i+1] == 0 {
			data = data[:i]
			break
		}
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, nil, err
	}
	return cert, data, nil
}

// SetSerialNumber inits the global serial number.
func SetSerialNumber(n int64) {
	serialNumber = n
}

// GetSerialNumber returns the new global serial number for certificate.
func GetSerialNumber() int64 {
	return atomic.AddInt64(&serialNumber, 1)
}

// GenerateCertificate generate a certificate according to template, signed by signer parent/key.
func GenerateCertificate(template, parent *x509.Certificate, pubDer []byte, signer crypto.PrivateKey) ([]byte, error) {
	if template == nil || parent == nil || len(pubDer) == 0 || signer == nil {
		return nil, ErrWrongParams
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubDer)
	if err != nil {
		return nil, err
	}

	template.SerialNumber = big.NewInt(GetSerialNumber())

	certDer, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, signer)
	if err != nil {
		return nil, err
	}
	return certDer, nil
}

// EncryptIKCert uses a random key to encrypt the IKCert and seals this random key with MakeCredential.
// Then only the coresponding TPM which has the EK could unseal this random key with ActiveCredential
// and decrypt the IKCert.
func EncryptIKCert(ekPubKey crypto.PublicKey, ikCert []byte, ikName []byte) (*IKCertChallenge, error) {
	key, err := GetRandomBytes(AesKeySize)
	if err != nil {
		return nil, err
	}
	iv, err := GetRandomBytes(AesKeySize)
	if err != nil {
		return nil, err
	}
	encIKCert, err := SymmetricEncrypt(AlgAES, AlgCBC, key, iv, ikCert)
	if err != nil {
		return nil, err
	}

	encKeyBlob, encSecret, err := MakeCredential(ekPubKey, key, ikName)
	if err != nil {
		return nil, err
	}

	symKeyParams := SymKeyParams{
		// encrypted secret by ekPub, use tpm2.ActivateCredential to decrypt and get secret
		EncryptedSecret: encSecret,
		// encrypted key by secret, use AES128 CFB to decrypt and get key
		CredBlob: encKeyBlob,
		// use this algorithm(AES128 CBC) + iv + key to decrypt ikCret
		EncryptAlg:   Encrypt_Alg,
		EncryptParam: iv,
	}
	ikCertChallenge := IKCertChallenge{
		// encrypted ikCert by key
		EncryptedCert: encIKCert,
		SymKeyParams:  symKeyParams,
	}
	return &ikCertChallenge, nil
}

// verifyComCert will get the all cert from certificate file to verify the cert is validated
func verifyComCert(pathname string, cert *x509.Certificate) bool {
	timeNow := time.Now()
	if !timeNow.Before(cert.NotAfter) {
		fmt.Println("The certificate has expired!")
		return false
	}
	rd, err := ioutil.ReadDir(pathname)
	if err != nil {
		return false
	}
	for _, fi := range rd {
		if !fi.IsDir() {
			ca, _, err := DecodeKeyCertFromFile(pathname + "/" + fi.Name())
			if err != nil {
				return false
			}
			if validateCert(cert, ca) == nil {
				return true
			}
		}
	}
	return false
}

// validateCert will check the signature is or not validated by parent cert
func validateCert(cert, parent *x509.Certificate) error {
	// check the period validate
	timeNow := time.Now()
	if !timeNow.Before(parent.NotAfter) {
		return errors.New("The certificate has expired")
	}
	if cert.Issuer.CommonName != parent.Subject.CommonName {
		return errors.New("cert issuer name is not the parent subject name")
	}
	err := parent.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		return err
	}
	return nil
}
