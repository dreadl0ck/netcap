/*
 * NETCAP - Traffic Analysis Framework
 * Copyright (c) Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 * License: GNU General Public License v3.0
 */

package cryptoutils

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	pub1, priv1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair failed: %v", err)
	}

	if pub1 == nil || priv1 == nil {
		t.Fatal("GenerateKeypair returned nil keys")
	}

	if len(pub1) != KeySize || len(priv1) != KeySize {
		t.Errorf("Key sizes incorrect: pub=%d, priv=%d, expected=%d", len(pub1), len(priv1), KeySize)
	}

	// Generate second pair and verify they differ
	pub2, priv2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Second GenerateKeypair failed: %v", err)
	}

	if bytes.Equal(pub1[:], pub2[:]) {
		t.Error("Two generated public keys should not be identical")
	}

	if bytes.Equal(priv1[:], priv2[:]) {
		t.Error("Two generated private keys should not be identical")
	}
}

func TestAsymmetricEncryptDecrypt(t *testing.T) {
	// Generate key pairs for sender and recipient
	senderPub, senderPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate sender keys: %v", err)
	}

	recipientPub, recipientPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate recipient keys: %v", err)
	}

	testMessages := [][]byte{
		[]byte("Hello, World!"),
		[]byte(""),
		[]byte("A"),
		bytes.Repeat([]byte("X"), 10000),
		{0x00, 0xFF, 0x01, 0xFE},
	}

	for i, original := range testMessages {
		// Encrypt with sender's private key and recipient's public key
		encrypted, err := AsymmetricEncrypt(original, recipientPub, senderPriv)
		if err != nil {
			t.Errorf("Test %d: Encryption failed: %v", i, err)
			continue
		}

		// Encrypted data should be longer than original (nonce + auth tag)
		if len(encrypted) < len(original)+nonceLen {
			t.Errorf("Test %d: Encrypted data too short", i)
		}

		// Decrypt with recipient's private key and sender's public key
		decrypted, ok := AsymmetricDecrypt(encrypted, senderPub, recipientPriv)
		if !ok {
			t.Errorf("Test %d: Decryption failed", i)
			continue
		}

		if !bytes.Equal(original, decrypted) {
			t.Errorf("Test %d: Decrypted data doesn't match original", i)
		}
	}
}

func TestAsymmetricDecryptInvalidInput(t *testing.T) {
	_, priv, _ := GenerateKeypair()
	pub, _, _ := GenerateKeypair()

	// Too short to contain nonce
	shortData := make([]byte, nonceLen-1)
	_, ok := AsymmetricDecrypt(shortData, pub, priv)
	if ok {
		t.Error("Decryption should fail for data shorter than nonce")
	}

	// Invalid ciphertext (random garbage)
	garbage := make([]byte, 100)
	_, ok = AsymmetricDecrypt(garbage, pub, priv)
	if ok {
		t.Error("Decryption should fail for invalid ciphertext")
	}
}

func TestAsymmetricDecryptWrongKey(t *testing.T) {
	senderPub, senderPriv, _ := GenerateKeypair()
	recipientPub, _, _ := GenerateKeypair()
	_, wrongPriv, _ := GenerateKeypair()

	original := []byte("Secret message")
	encrypted, _ := AsymmetricEncrypt(original, recipientPub, senderPriv)

	// Try to decrypt with wrong private key
	_, ok := AsymmetricDecrypt(encrypted, senderPub, wrongPriv)
	if ok {
		t.Error("Decryption should fail with wrong private key")
	}
}

func TestMD5Data(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected [16]byte
	}{
		{
			input:    []byte(""),
			expected: md5.Sum([]byte("")),
		},
		{
			input:    []byte("hello"),
			expected: md5.Sum([]byte("hello")),
		},
		{
			input:    []byte("The quick brown fox jumps over the lazy dog"),
			expected: md5.Sum([]byte("The quick brown fox jumps over the lazy dog")),
		},
	}

	for i, tc := range testCases {
		result := MD5Data(tc.input)
		if !bytes.Equal(result, tc.expected[:]) {
			t.Errorf("Test %d: MD5 mismatch for input %q", i, tc.input)
		}
	}

	// Verify output length
	result := MD5Data([]byte("test"))
	if len(result) != 16 {
		t.Errorf("MD5 output length incorrect: got %d, expected 16", len(result))
	}
}

func TestRandomString(t *testing.T) {
	lengths := []int{0, 1, 5, 10, 20, 50, 100}

	for _, length := range lengths {
		result, err := RandomString(length)
		if err != nil {
			t.Errorf("RandomString(%d) failed: %v", length, err)
			continue
		}

		if len(result) != length {
			t.Errorf("RandomString(%d) returned string of length %d", length, len(result))
		}
	}

	// Verify randomness - two calls should produce different results
	str1, _ := RandomString(32)
	str2, _ := RandomString(32)
	if str1 == str2 {
		t.Error("Two RandomString calls should produce different results")
	}
}

func TestRandomStringCharacters(t *testing.T) {
	// Verify output contains only URL-safe base64 characters
	result, err := RandomString(100)
	if err != nil {
		t.Fatalf("RandomString failed: %v", err)
	}

	validChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
	for _, c := range result {
		found := false
		for _, v := range validChars {
			if c == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Invalid character in RandomString output: %c", c)
		}
	}
}

func BenchmarkGenerateKeypair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = GenerateKeypair()
	}
}

func BenchmarkAsymmetricEncrypt(b *testing.B) {
	senderPub, senderPriv, _ := GenerateKeypair()
	recipientPub, _, _ := GenerateKeypair()
	_ = senderPub // sender pub key not used in encryption
	message := bytes.Repeat([]byte("X"), 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = AsymmetricEncrypt(message, recipientPub, senderPriv)
	}
}

func BenchmarkMD5Data(b *testing.B) {
	data := bytes.Repeat([]byte("X"), 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MD5Data(data)
	}
}

