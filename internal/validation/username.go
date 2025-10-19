package validation

import (
	"fmt"
	"regexp"
)

// UsernamePattern определяет допустимый формат username
// Только латинские буквы (a-z, A-Z), цифры (0-9), нижнее подчеркивание (_)
// Длина: 3-32 символа
var UsernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,32}$`)

const (
	// MinUsernameLen минимальная длина username
	MinUsernameLen = 3
	// MaxUsernameLen максимальная длина username
	MaxUsernameLen = 32
)

// ValidateUsername проверяет, что username соответствует требованиям
// Формат: только латинские буквы (a-z, A-Z), цифры (0-9), нижнее подчеркивание (_)
// Длина: 3-32 символа
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) < MinUsernameLen {
		return fmt.Errorf("username must be at least %d characters long", MinUsernameLen)
	}

	if len(username) > MaxUsernameLen {
		return fmt.Errorf("username must not exceed %d characters", MaxUsernameLen)
	}

	if !UsernamePattern.MatchString(username) {
		return fmt.Errorf("username can only contain letters (a-z, A-Z), numbers (0-9), and underscores (_)")
	}

	return nil
}

// ValidatePassword проверяет минимальные требования к master password
// Минимум 12 символов
func ValidatePassword(password string) error {
	const minPasswordLen = 12

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLen)
	}

	return nil
}
