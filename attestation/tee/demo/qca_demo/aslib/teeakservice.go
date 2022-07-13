// Description: Access interface of the AS provided for QCA

package aslib

import (
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

func GetAKCert(oldAKCert []byte) ([]byte, error) {
	req := clientapi.GetAKCertRequest{
		Akcert: oldAKCert,
	}
	rpy, err := clientapi.DoGetAKCert(qcatools.Qcacfg.AKServer, &req)
	if err != nil {
		log.Printf("Get AKCert failed, error: %v", err)
		return nil, err
	}
	newCert := rpy.GetAkcert()
	return newCert, nil
}
