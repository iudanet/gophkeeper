package crypto

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// BcryptCost определяет стоимость bcrypt (по умолчанию DefaultCost = 10)
// Более высокое значение = медленнее, но безопаснее
const BcryptCost = bcrypt.DefaultCost

// HashAuthKey хеширует auth_key с использованием bcrypt
// Используется на клиенте перед отправкой на сервер
// и на сервере для хранения в базе данных
func HashAuthKey(authKey []byte) (string, error) {
	if len(authKey) == 0 {
		return "", fmt.Errorf("auth key cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword(authKey, BcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash auth key: %w", err)
	}

	return string(hashedBytes), nil
}

// VerifyAuthKey проверяет, соответствует ли auth_key сохраненному хешу
// Используется на сервере для аутентификации пользователя
func VerifyAuthKey(authKey []byte, hashedAuthKey string) error {
	if len(authKey) == 0 {
		return fmt.Errorf("auth key cannot be empty")
	}
	if hashedAuthKey == "" {
		return fmt.Errorf("hashed auth key cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedAuthKey), authKey)
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return fmt.Errorf("invalid auth key")
		}
		return fmt.Errorf("failed to verify auth key: %w", err)
	}

	return nil
}
