package config

import (
	"testing"
	"time"
)

const (
	testString1 = "abcdef12345"
	testString2 = "123#$%^&*()!@#"
	testString3 = "zxcdfeaonasdfasdf"
)

func TestRASConfig(t *testing.T) {
	config := GetDefault()

	testCases1 := []struct {
		input  string
		result string
	}{
		{testString1, testString1},
		{testString2, testString2},
		{testString3, testString3},
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetMgrStrategy(testCases1[i].input)
		if config.GetMgrStrategy() != testCases1[i].result {
			t.Errorf("test mgrStrategy error at case %d\n", i)
		}
	}
}

func TestRACConfig(t *testing.T) {
	config := GetDefault()

	testCases1 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases1); i++ {
		config.SetHBDuration(testCases1[i].input)
		if config.GetHBDuration() != testCases1[i].result {
			t.Errorf("test hbDuration error at case %d\n", i)
		}
	}

	testCases2 := []struct {
		input  time.Duration
		result time.Duration
	}{
		{time.Second, time.Second},
		{time.Hour, time.Hour},
	}
	for i := 0; i < len(testCases2); i++ {
		config.SetTrustDuration(testCases2[i].input)
		if config.GetTrustDuration() != testCases2[i].result {
			t.Errorf("test trustDuration error at case %d\n", i)
		}
	}
}
