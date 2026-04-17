package goauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func decodeEncryptionKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty key")
	}

	// Try hex first.
	if b, err := hex.DecodeString(raw); err == nil && isValidAESKeySize(len(b)) {
		return b, nil
	}

	// Try standard/base64url.
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && isValidAESKeySize(len(b)) {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil && isValidAESKeySize(len(b)) {
		return b, nil
	}

	// Fall back to literal bytes.
	b := []byte(raw)
	if isValidAESKeySize(len(b)) {
		return b, nil
	}
	return nil, fmt.Errorf("must decode to 16, 24, or 32 bytes")
}

func isValidAESKeySize(n int) bool {
	return n == 16 || n == 24 || n == 32
}

func encryptSecret(secret string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	out := append(nonce, ciphertext...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func decryptSecret(cipherTextB64 string, key []byte) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(cipherTextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
