// An interface provided to attester
package qapi

import (
	"context"

	"gitee.com/openeuler/kunpengsecl/attestation/demo/qca_demo/qcatools"
)

func DoGetInfo(ctx context.Context, in *GetInfoRequest) (*GetInfoReply, error) {
	_ = ctx // ignore the unused warning
	rep := qcatools.GetInfo(in.Identity)
	rpy := GetInfoReply{
		Uuid:      rep.Uuid,
		Quoted:    rep.Quoted,
		Signature: rep.Signature,
		Cert:      rep.Cert,
		Manifest:  rep.Manifest,
	}
	return &rpy, nil
}
