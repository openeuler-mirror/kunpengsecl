package dao

import (
	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

/*
	dao is an interface for processing data in database
 */
type dao interface {
	SaveReport(report entity.Report) error
}
