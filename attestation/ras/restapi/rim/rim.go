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
	"fmt"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// ParseRIM validates the give rim XML with the given cert as the root signing cert,
// with dAlg as the expected digest algorithm, returns the referece value
// in ima format string.
func ParseRIM(rim []byte, cert *x509.Certificate, dAlg string) (ima string, err error) {
	doc := etree.NewDocument()
	err = doc.ReadFromBytes(rim)
	if err != nil {
		return
	}

	doc2, err := validate(cert, doc.Root())
	if err != nil {
		return
	}

	ima, err = rim2ima(doc2, dAlg)
	if err != nil {
		return
	}

	return
}

// Convert all File elements in RIM file to ima reference format
func rim2ima(doc *etree.Document, dAlg string) (ima string, err error) {
	els := doc.FindElements("//File")
	for _, f := range els {
		head := f.Parent().SelectAttrValue("location", "") + f.Parent().SelectAttrValue("name", "")
		if head != "/" && head != "" {
			head += "/"
		}
		ima += fmt.Sprintf(
			"ima-ng %s:%s %s\n",
			dAlg,
			f.SelectAttrValue(strings.ToUpper(dAlg)+":hash", ""),
			head+f.SelectAttrValue("name", ""))
	}

	return
}

// Validate an element against a root certificate, and return the validated portion
func validate(root *x509.Certificate, el *etree.Element) (doc *etree.Document, err error) {
	// Construct a signing context with one or more roots of trust.
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{root},
	})

	v, err := ctx.Validate(el)
	if err != nil {
		println(err)
		return
	}

	doc = etree.NewDocument()
	doc.SetRoot(v)

	return
}
