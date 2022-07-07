/***
Description: Access interface of the AS provided for QCA
***/

package aslib

import (
	"log"

	"gitee.com/openeuler/kunpengsecl/attestation/tas/clientapi"
	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

func GetAKCert(oldAKCert []byte, dvcert []byte) ([]byte, error) {
	req := clientapi.GetAKCertRequest{
		Akcert: oldAKCert,
		Dvcert: dvcert,
	}
	rpy, err := clientapi.DoGetAKCert(qcatools.Qcacfg.AKServer, &req)
	if err != nil {
		log.Printf("Get AKCert failed, error: %v", err)
		return nil, err
	}
	newCert := rpy.GetAkcert()
	return newCert, nil
}

func RegisterClient(clientinfo string, dvcert []byte) int64 {
	req := clientapi.RegisterClientRequest{
		Clientinfo: clientinfo,
		Dvcert:     dvcert,
	}
	rpy, err := clientapi.DoRegisterClient(qcatools.Qcacfg.AKServer, &req)
	if err != nil {
		log.Printf("Register client failed, error: %v", err)
		return -1
	}
	cid := rpy.GetClientid()
	return cid
}
