/*
Copyright (c) Huawei Technologies Co., Ltd. 2021.
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2.
You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
PURPOSE.
See the Mulan PSL v2 for more details.

Author: wucaijun/lixinda
Create: 2021-11-12
Description: Implement a privacy CA to sign identity key(AIK).

<<A Practical Guide to TPM2.0>>
	--Using the Trusted Platform Module in the New Age of Security
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
5.        Generate Seed, encrypt Seed <=
              with TPM Encryption Key
6.     Use Seed in KDF (with Name) to <=
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

package pca

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
)

var (
	ErrUnsupported = errors.New("unsupported parameters")
)

// GetRandomBytes gets true random bytes form TPM(true) or from simulator(false)
func GetRandomBytes(size int, fromTPM bool) (b []byte, err error) {
	var rw io.ReadWriteCloser
	if fromTPM {
		rw, err = tpm2.OpenTPM("/dev/tpmrm0")
	} else {
		rw, err = simulator.Get()
	}
	if err != nil {
		return []byte{}, err
	}
	defer rw.Close()
	b, err = tpm2.GetRandom(rw, uint16(size))
	if err != nil {
		return []byte{}, err
	}
	return b, nil
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
	st := cipher.NewCTR(cb, iv)
	out := make([]byte, len(in))
	st.XORKeyStream(out, in)
	return out, nil
}

// SymmetricEncrypt uses key/iv to encrypt the plaintext with symmetric algorithm/mode.
func SymmetricEncrypt(alg, mod tpm2.Algorithm, key, iv, plaintext []byte) ([]byte, error) {
	switch alg {
	case tpm2.AlgAES:
		switch mod {
		case tpm2.AlgCBC:
			return aesCBCEncrypt(key, iv, plaintext)
		case tpm2.AlgCFB:
			return aesCFBEncrypt(key, iv, plaintext)
		case tpm2.AlgOFB:
			return aesOFBEncDec(key, iv, plaintext)
		case tpm2.AlgCTR:
			return aesCTREncDec(key, iv, plaintext)
		}
	}
	return []byte{}, ErrUnsupported
}

// SymmetricDecrypt uses key/iv to decrypt the ciphertext with symmetric algorithm/mode.
func SymmetricDecrypt(alg, mod tpm2.Algorithm, key, iv, ciphertext []byte) ([]byte, error) {
	switch alg {
	case tpm2.AlgAES:
		switch mod {
		case tpm2.AlgCBC:
			return aesCBCDecrypt(key, iv, ciphertext)
		case tpm2.AlgCFB:
			return aesCFBDecrypt(key, iv, ciphertext)
		case tpm2.AlgOFB:
			return aesOFBEncDec(key, iv, ciphertext)
		case tpm2.AlgCTR:
			return aesCTREncDec(key, iv, ciphertext)
		}
	}
	return []byte{}, ErrUnsupported
}
