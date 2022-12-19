// Description: Access interface of the AS provided for QCA

package aslib

import (
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
)

func GetAKCert(addr string, oldAKCert []byte, scenario int32) ([]byte, error) {
	req := clientapi.GetAKCertRequest{
		Akcert:   oldAKCert,
		Scenario: scenario,
	}
	rpy, err := clientapi.DoGetAKCert(addr, &req)
	if err != nil {
		log.Printf("Get AKCert failed, error: %v", err)
		return nil, err
	}
	newCert := rpy.GetAkcert()
	return newCert, nil
}
