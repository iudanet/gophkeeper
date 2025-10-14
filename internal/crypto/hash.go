package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HashAuthKey хеширует auth_key с использованием SHA256
// Используется на клиенте и сервере для детерминированного хеширования
// auth_key уже защищен через Argon2id, SHA256 добавляет дополнительный слой
func HashAuthKey(authKey []byte) (string, error) {
	if len(authKey) == 0 {
		return "", fmt.Errorf("auth key cannot be empty")
	}

	// SHA256 хеширование
	hash := sha256.Sum256(authKey)

	// Возвращаем hex-encoded строку
	return hex.EncodeToString(hash[:]), nil
}

// VerifyAuthKey проверяет, соответствует ли auth_key сохраненному хешу
// Используется на сервере для аутентификации пользователя
// Просто сравнивает два SHA256 хеша (детерминированные)
func VerifyAuthKey(authKey []byte, hashedAuthKey string) error {
	if len(authKey) == 0 {
		return fmt.Errorf("auth key cannot be empty")
	}
	if hashedAuthKey == "" {
		return fmt.Errorf("hashed auth key cannot be empty")
	}

	// Вычисляем хеш от переданного ключа
	computedHash, err := HashAuthKey(authKey)
	if err != nil {
		return fmt.Errorf("failed to compute auth key hash: %w", err)
	}

	// Сравниваем хеши
	if computedHash != hashedAuthKey {
		return fmt.Errorf("invalid auth key")
	}

	return nil
}
