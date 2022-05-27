// An interface provided to attester
package qapi

import (
	"context"
	"fmt"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

func DoGetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error) {
	_ = ctx // ignore the unused warning
	qcatools.Usrdata = in.GetNonce()
	rep := qcatools.GetTAReport(in.GetUuid(), qcatools.Usrdata, in.WithTcb)
	rpy := GetReportReply{
		TeeReport: rep,
	}
	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(rpy.TeeReport.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, rpy.TeeReport.Buf[i])
	// }
	fmt.Print("\n")
	return &rpy, nil
}
