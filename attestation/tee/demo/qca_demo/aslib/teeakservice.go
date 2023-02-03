/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: wangli
Create: 2022-04-20
Description: Access interface of the AS provided for QCA
*/

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
