package sm3

import (
	"testing"
)

func TestSM3Hash(t *testing.T) {
	data := []byte("Hello, SM3!")
	hash, err := SM3Hash(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 {
		t.Fatalf("invalid hash length: %d", len(hash))
	}
}