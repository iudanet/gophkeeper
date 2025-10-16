package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Keys содержит производные ключи для аутентификации и шифрования
type Keys struct {
	AuthKey       []byte // ключ для аутентификации на сервере (32 bytes)
	EncryptionKey []byte // ключ для шифрования данных (32 bytes)
}

// Параметры Argon2id согласно технической спецификации
const (
	// Argon2Time - количество итераций (time cost)
	Argon2Time = 1
	// Argon2Memory - объем памяти в KB (64MB = 64*1024 KB)
	Argon2Memory = 64 * 1024
	// Argon2Threads - количество параллельных потоков
	Argon2Threads = 4
	// Argon2KeyLen - длина выходного ключа в байтах
	Argon2KeyLen = 32
	// SaltSize - размер соли в байтах
	SaltSize = 32
)

// GenerateSalt генерирует криптографически случайную соль указанного размера
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateSaltBase64 генерирует криптографически случайную соль и возвращает ее в Base64
func GenerateSaltBase64() (string, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// DeriveKeys генерирует два независимых ключа из master password:
// - AuthKey для аутентификации на сервере
// - EncryptionKey для шифрования данных
// Использует Argon2id с разными context strings для независимости ключей
func DeriveKeys(masterPassword, username string, salt []byte) (*Keys, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("master password cannot be empty")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be %d bytes, got %d", SaltSize, len(salt))
	}

	// Создаем базовый материал для деривации
	baseInput := []byte(masterPassword + username)

	// Генерируем AuthKey с context "auth"
	authContext := append(baseInput, []byte("auth")...)
	authKey := argon2.IDKey(authContext, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Генерируем EncryptionKey с context "encrypt"
	encryptContext := append(baseInput, []byte("encrypt")...)
	encryptionKey := argon2.IDKey(encryptContext, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	return &Keys{
		AuthKey:       authKey,
		EncryptionKey: encryptionKey,
	}, nil
}

// DeriveKeysFromBase64Salt генерирует ключи из Base64-кодированной соли
func DeriveKeysFromBase64Salt(masterPassword, username, saltBase64 string) (*Keys, error) {
	salt, err := base64.StdEncoding.DecodeString(saltBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}
	return DeriveKeys(masterPassword, username, salt)
}
