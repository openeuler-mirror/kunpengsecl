// An interface provided to attester
package qapi

import (
	"context"
	"fmt"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

var (
	brep *Buffer = &Buffer{
		Size: 0,
		Buf:  nil,
	}
)

func DoGetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error) {
	_ = ctx // ignore the unused warning
	qcatools.Usrdata.Size = in.UsrData.Size
	qcatools.Usrdata.Buf = in.UsrData.Buf
	qcatools.Paramset.Size = in.ParamSet.Size
	qcatools.Paramset.Buf = in.ParamSet.Buf
	qcatools.Report.Size = in.Report.Size
	qcatools.Report.Buf = in.Report.Buf
	rep, nonce := qcatools.GetTAReport(in.Uuid, qcatools.Usrdata, qcatools.Paramset, qcatools.Report, in.WithTcb)
	brep.Size = rep.Size
	brep.Buf = rep.Buf
	rpy := GetReportReply{
		TeeReport: brep,
		Nonce:     nonce,
	}
	// log.Print("Get TA report success:\n")
	// for i := 0; i < int(rpy.TeeReport.Size); i++ {
	// 	fmt.Printf("index%d is 0x%x; ", i, rpy.TeeReport.Buf[i])
	// }
	fmt.Print("\n")
	return &rpy, nil
}
