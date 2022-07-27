package cache

import (
	"testing"
	"time"

	"gitee.com/openeuler/kunpengsecl/attestation/common/cryptotools"
	"gitee.com/openeuler/kunpengsecl/attestation/common/typdefs"
)

var testCases1 = []time.Duration{time.Second, time.Second * 3, time.Millisecond * 10}

func TestHeartBeat(t *testing.T) {
	for i := 0; i < len(testCases1); i++ {
		c := NewCache()
		c.UpdateHeartBeat(testCases1[i])
		if !c.online {
			t.Errorf("test UpdateHeartBeat error at case %d\n", i)
		}
		time.Sleep(testCases1[i] / 2)
		b1 := c.IsHeartBeatExpired()
		time.Sleep(testCases1[i])
		b2 := c.IsHeartBeatExpired()
		if b1 || !b2 {
			t.Errorf("test IsHeartBeatExpired error at case %d\n", i)
		}
	}
}

func TestUpdateTrustReport(t *testing.T) {
	for i := 0; i < len(testCases1); i++ {
		c := NewCache()
		c.UpdateTrustReport(testCases1[i])
		if c.GetTrustExpiration().Sub(time.Now().Add(testCases1[i])) > time.Microsecond {
			t.Errorf("test UpdateTrustReport error at case %d\n", i)
		}
	}
}

func TestOnline(t *testing.T) {
	for i := 0; i < len(testCases1); i++ {
		c := NewCache()
		o1 := c.GetOnline()
		c.UpdateOnline(testCases1[i])
		o2 := c.GetOnline()
		if c.onlineExpiration.Sub(time.Now().Add(testCases1[i])) > time.Microsecond {
			t.Errorf("test UpdateOnline error at case %d\n", i)
		}
		time.Sleep(testCases1[i] * 2)
		o3 := c.GetOnline()

		if o1 || !o2 || o3 {
			t.Errorf("test GetOnline error at case %d\n", i)
		}
	}
}

func TestCommands(t *testing.T) {
	testCases2 := []uint64{typdefs.CmdGetReport, typdefs.CmdSendConfig}
	for i := 0; i < len(testCases2); i++ {
		c := NewCache()
		o1 := c.HasCommands()
		c.SetCommands(testCases2[i])
		o2 := c.HasCommands()
		if c.GetCommands() != testCases2[i] {
			t.Errorf("test SetCommands and GetCommands error at case %d\n", i)
		}
		c.ClearCommands()
		o3 := c.HasCommands()
		if o1 || !o2 || o3 {
			t.Errorf("test ClearCommands and HasCommands error at case %d\n", i)
		}
	}
}

func TestTrusted(t *testing.T) {
	testCases2 := []string{"trusted", "untrusted", "unknown"}
	for i := 0; i < len(testCases2); i++ {
		c := NewCache()
		c.trustExpiration = time.Now().Add(time.Second * 3)
		c.SetTrusted(testCases2[i])
		c.online = true
		if c.GetTrusted() != testCases2[i] {
			t.Errorf("test Trusted error at case %d\n", i)
		}
	}
}

func TestNonce(t *testing.T) {
	c := NewCache()
	n := c.GetNonce()
	c.nonce = n
	if !c.CompareNonce(n) {
		t.Errorf("test Nonce error")
	}
}

func TestIKeyCert(t *testing.T) {
	testCases2 := []string{"abcdef12345", "123#$%^&*()!@#", "zxcdfeaonasdfasdf"}
	for i := 0; i < len(testCases2); i++ {
		c := NewCache()
		c.SetIKeyCert(testCases2[i])
		got := c.GetIKeyCert()
		want, _, _ := cryptotools.DecodeKeyCertFromPEM([]byte(testCases2[i]))
		if got != want {
			t.Errorf("test IKeyCert error at case %d\n", i)
		}
	}
}

func TestRegTime(t *testing.T) {
	testCases2 := []string{"abcdef12345", "123#$%^&*()!@#", "zxcdfeaonasdfasdf"}
	for i := 0; i < len(testCases1); i++ {
		c := NewCache()
		c.SetRegTime(testCases2[i])
		if c.GetRegTime() != testCases2[i] {
			t.Errorf("test RegTime error at case %d\n", i)
		}
	}
}

func TestIsAutoUpdate(t *testing.T) {
	testCases2 := []bool{true, false}
	for i := 0; i < len(testCases2); i++ {
		c := NewCache()
		c.SetIsAutoUpdate(testCases2[i])
		if c.GetIsAutoUpdate() != testCases2[i] {
			t.Errorf("test IsAutoUpdate error at case %d\n", i)
		}
	}
}
