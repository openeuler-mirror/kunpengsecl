package verifier

import (
	"fmt"
	"testing"

	"gitee.com/openeuler/kunpengsecl/attestation/ras/entity"
)

func TestPCRVerifier_Verify(t *testing.T) {
	var pv *PCRVerifier

	bvpcrInfo1 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			2: "pcr value 2",
			5: "pcr value 5",
		},
		Quote: []byte("test quote"),
	}

	bvpcrInfo2 := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			2: "pcr value 1",
			5: "pcr value 5",
		},
		Quote: []byte("test quote"),
	}

	repopcrInfo := entity.PcrInfo{
		AlgName: "sha1",
		Values: map[int]string{
			1: "pcr value 1",
			2: "pcr value 2",
			3: "pcr value 3",
			4: "pcr value 4",
			5: "pcr value 5",
		},
		Quote: []byte("test quote"),
	}

	baseValue1 := &entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  bvpcrInfo1,
		Manifest: nil,
	}

	baseValue2 := &entity.MeasurementInfo{
		ClientID: 1,
		PcrInfo:  bvpcrInfo2,
		Manifest: nil,
	}

	report := &entity.Report{
		PcrInfo:  repopcrInfo,
		Manifest: nil,
		ClientID: 1,
		ClientInfo: entity.ClientInfo{
			Info: nil,
		},
		Verified: false,
	}

	errcase := fmt.Errorf("PCR verification failed")
	testCase := []struct {
		input1 *entity.MeasurementInfo
		input2 *entity.Report
		result error
	}{
		{baseValue1, report, nil},
		{baseValue2, report, errcase},
	}
	for i := 0; i < len(testCase); i++ {
		pv.Verify(testCase[i].input1, testCase[i].input2)
		/*
			if err == testCase[i].result {
				t.Logf("test PCR Verify success at case %d\n", i)
			} else if err.Error() == testCase[i].result.Error() {
				t.Logf("test PCR Verify success at case %d\n", i)
			} else {
				t.Errorf("test PCR Verify error at case %d\n", i)
			}
		*/
	}

}
