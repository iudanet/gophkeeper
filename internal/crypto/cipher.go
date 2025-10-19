package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

const (
	// NonceSize - размер nonce для AES-GCM (12 bytes стандартный размер)
	NonceSize = 12
)

// Encrypt шифрует данные с использованием AES-256-GCM
// Формат результата: nonce (12 bytes) + ciphertext + auth_tag (16 bytes)
// Возвращает зашифрованные данные в виде байтов
func Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	// Создаем AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Создаем GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Генерируем случайный nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Шифруем данные
	// GCM автоматически добавляет authentication tag в конец
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Формируем результат: nonce + ciphertext + auth_tag
	result := make([]byte, 0, len(nonce)+len(ciphertext))
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// EncryptToBase64 шифрует данные и возвращает результат в Base64
// Удобно для передачи по сети и хранения в JSON
func EncryptToBase64(plaintext, key []byte) (string, error) {
	encrypted, err := Encrypt(plaintext, key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt дешифрует данные, зашифрованные с помощью Encrypt
// Ожидает формат: nonce (12 bytes) + ciphertext + auth_tag (16 bytes)
func Decrypt(encrypted, key []byte) ([]byte, error) {
	if len(encrypted) < NonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	// Создаем AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Создаем GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Извлекаем nonce из первых 12 bytes
	nonce := encrypted[:NonceSize]
	ciphertext := encrypted[NonceSize:]

	// Дешифруем и проверяем authentication tag
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: authentication failed or corrupted data: %w", err)
	}

	return plaintext, nil
}

// DecryptFromBase64 дешифрует данные из Base64
func DecryptFromBase64(encryptedBase64 string, key []byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return Decrypt(encrypted, key)
}
