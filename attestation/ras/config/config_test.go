package config

import (
	"fmt"
	"github.com/magiconair/properties/assert"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	config, err := CreateConfig()
	if err != nil {
		t.FailNow()
	}
	// change and test
	config.SetHBDuration(time.Second*2)
	config.SetTrustDuration(time.Minute*2)
	config.SetMgrStrategy("auto")
	config.ChangeConfig(time.Second*2, time.Minute*2, "auto")
	hd := config.GetHBDuration()
	td := config.GetTrustDuration()
	ms := config.GetMgrStrategy()
	ct := config.GetChangeTime()
	assert.Equal(t, hd, time.Second*2, "hbDuration error")
	assert.Equal(t, td, time.Minute*2, "trustDuration error")
	assert.Equal(t, ms, "auto", "MgrStrategy error")
	fmt.Printf("change changeTime: %s\n", ct)
}
