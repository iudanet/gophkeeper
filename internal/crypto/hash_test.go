package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashAuthKey(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		authKey []byte
		wantErr bool
	}{
		{
			name:    "successful hash",
			authKey: []byte("test_auth_key_12345678901234567890"),
			wantErr: false,
		},
		{
			name:    "empty auth key",
			authKey: []byte{},
			wantErr: true,
			errMsg:  "auth key cannot be empty",
		},
		{
			name:    "nil auth key",
			authKey: nil,
			wantErr: true,
			errMsg:  "auth key cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedAuthKey, err := HashAuthKey(tt.authKey)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Empty(t, hashedAuthKey)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, hashedAuthKey)

				// SHA256 хеш всегда 64 символа (hex-encoded, 32 bytes * 2)
				assert.Len(t, hashedAuthKey, 64, "SHA256 hash должен быть 64 символа")

				// Проверяем, что это валидный hex
				assert.Regexp(t, "^[a-f0-9]{64}$", hashedAuthKey, "должен быть hex-encoded")
			}
		})
	}
}

func TestHashAuthKey_Deterministic(t *testing.T) {
	// Проверяем, что SHA256 детерминирован (одинаковый вход = одинаковый хеш)
	authKey := []byte("test_auth_key_123")

	hash1, err1 := HashAuthKey(authKey)
	require.NoError(t, err1)

	hash2, err2 := HashAuthKey(authKey)
	require.NoError(t, err2)

	// Хеши должны быть одинаковыми (детерминированность SHA256)
	assert.Equal(t, hash1, hash2, "SHA256 должен генерировать одинаковые хеши для одинаковых входных данных")
}

func TestHashAuthKey_KnownVector(t *testing.T) {
	// Тест с известным вектором
	authKey := []byte("test")
	expectedHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" // SHA256("test")

	hash, err := HashAuthKey(authKey)
	require.NoError(t, err)
	assert.Equal(t, expectedHash, hash)
}

func TestVerifyAuthKey(t *testing.T) {
	// Сначала создаем валидный хеш
	validAuthKey := []byte("my_secret_auth_key")
	validHash, err := HashAuthKey(validAuthKey)
	require.NoError(t, err)

	tests := []struct {
		name          string
		hashedAuthKey string
		errMsg        string
		authKey       []byte
		wantErr       bool
	}{
		{
			name:          "successful verification",
			authKey:       validAuthKey,
			hashedAuthKey: validHash,
			wantErr:       false,
		},
		{
			name:          "invalid auth key",
			authKey:       []byte("wrong_auth_key"),
			hashedAuthKey: validHash,
			wantErr:       true,
			errMsg:        "invalid auth key",
		},
		{
			name:          "empty auth key",
			authKey:       []byte{},
			hashedAuthKey: validHash,
			wantErr:       true,
			errMsg:        "auth key cannot be empty",
		},
		{
			name:          "empty hashed auth key",
			authKey:       validAuthKey,
			hashedAuthKey: "",
			wantErr:       true,
			errMsg:        "hashed auth key cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAuthKey(tt.authKey, tt.hashedAuthKey)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestHashAndVerify_Integration(t *testing.T) {
	// Интеграционный тест: хешируем и проверяем
	authKeys := [][]byte{
		[]byte("auth_key_1"),
		[]byte("another_auth_key_12345"),
		[]byte("very_long_auth_key_with_many_characters_0123456789"),
	}

	for _, authKey := range authKeys {
		t.Run(string(authKey), func(t *testing.T) {
			// Хешируем
			hashedAuthKey, err := HashAuthKey(authKey)
			require.NoError(t, err)

			// Проверяем правильный ключ
			err = VerifyAuthKey(authKey, hashedAuthKey)
			require.NoError(t, err, "верный ключ должен пройти проверку")

			// Проверяем неправильный ключ
			wrongKey := append(authKey, []byte("_wrong")...)
			err = VerifyAuthKey(wrongKey, hashedAuthKey)
			require.Error(t, err, "неверный ключ не должен пройти проверку")
		})
	}
}
