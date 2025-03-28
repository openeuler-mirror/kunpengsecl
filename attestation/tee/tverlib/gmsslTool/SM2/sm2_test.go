package sm2

import (
	"testing"
)

// func TestSM2SignVerify(t *testing.T) {
// 	pub, priv, err := GenerateSM2KeyPair()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	data := []byte("Hello, SM2!")
// 	sig, err := SM2Sign(priv, data)
// 	if err != nil {
// 		t.Fatal("sign failed:", err)
// 	}

//		valid, err := SM2Verify(pub, data, sig)
//		if err != nil || !valid {
//			t.Fatal("verify failed:", err)
//		}
//	}
func TestSM2SignVerify(t *testing.T) {
	pub, priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	t.Logf("公钥:\n%s\n私钥:\n%s", pub, priv) // 打印密钥

	data := []byte("test data")
	sig, err := SM2Sign(priv, data)
	if err != nil {
		t.Fatalf("签名失败: %v", err) // 明确失败原因
	}

	valid, err := SM2Verify(pub, data, sig)
	if err != nil || !valid {
		t.Fatal("verify failed:", err)
	}
}
