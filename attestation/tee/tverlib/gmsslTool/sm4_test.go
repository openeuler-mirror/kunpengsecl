package sm4

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// 测试辅助函数：生成随机字节
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// 测试用例1：常规短文本加密解密
func TestShortText(t *testing.T) {
	plaintext := []byte("SM4测试")
	const KeySize = 16
	key, err := randomBytes(KeySize)
	if err != nil {
		t.Fatalf("生成随机密钥失败: %v", err)
	}

	ciphertext, iv, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	decrypted, err := SM4Decrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("解密结果与原文不符")
	}
}

// 测试用例2：长文本加密解密
func TestLongText(t *testing.T) {
	plaintext := bytes.Repeat([]byte("Go语言SM4测试-"), 100) // 约1.5KB数据
	const KeySize = 16
	key, err := randomBytes(KeySize)
	if err != nil {
		t.Fatalf("生成随机密钥失败: %v", err)
	}

	ciphertext, iv, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := SM4Decrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("长文本解密结果不一致")
	}
}

// 测试用例3：二进制数据加密解密
func TestBinaryData(t *testing.T) {
	plaintext, err := randomBytes(512) // 512字节随机数据
	if err != nil {
		t.Fatalf("生成随机数据失败: %v", err)
	}

	const KeySize = 16
	key, err := randomBytes(KeySize)
	if err != nil {
		t.Fatalf("生成随机密钥失败: %v", err)
	}

	ciphertext, iv, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := SM4Decrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("二进制数据解密失败")
	}
}

// 测试用例4：多次加密结果不同（因IV随机）
func TestRandomIV(t *testing.T) {
	plaintext := []byte("相同输入不同IV")
	const KeySize = 16
	key, err := randomBytes(KeySize)
	if err != nil {
		t.Fatalf("生成随机密钥失败: %v", err)
	}

	// 第一次加密
	ciphertext1, iv1, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	// 第二次加密
	ciphertext2, iv2, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatal(err)
	}

	// IV必须不同
	if bytes.Equal(iv1, iv2) {
		t.Fatal("IV未随机化")
	}

	// 密文应该不同
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatal("相同输入生成相同密文，存在安全风险")
	}
}
