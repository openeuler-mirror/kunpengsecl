// An interface provided to attester
package qapi

import (
	"context"

	"gitee.com/openeuler/kunpengsecl/attestation/tee/demo/qca_demo/qcatools"
)

var (
	usrdata *qcatools.Go_ra_buffer_data = &qcatools.Go_ra_buffer_data{ // Pointers should be initialized correctly!!!
		Size: 0,
		Buf:  nil,
	}
	paramset *qcatools.Go_ra_buffer_data = &qcatools.Go_ra_buffer_data{
		Size: 0,
		Buf:  nil,
	}
	report *qcatools.Go_ra_buffer_data = &qcatools.Go_ra_buffer_data{
		Size: 0,
		Buf:  nil,
	}
	brep *Buffer = &Buffer{
		Size: 0,
		Buf:  nil,
	}
)

func DoGetReport(ctx context.Context, in *GetReportRequest) (*GetReportReply, error) {
	_ = ctx // ignore the unused warning
	usrdata.Size = in.UsrData.Size
	usrdata.Buf = in.UsrData.Buf
	paramset.Size = in.ParamSet.Size
	paramset.Buf = in.ParamSet.Buf
	report.Size = in.Report.Size
	report.Buf = in.Report.Buf
	rep := qcatools.GetTAReport(in.Uuid, usrdata, report, paramset, in.WithTcb)
	brep.Size = rep.Size
	brep.Buf = rep.Buf
	rpy := GetReportReply{
		TeeReport: brep,
	}
	return &rpy, nil
}
