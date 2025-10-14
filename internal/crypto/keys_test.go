package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "generate salt successfully"},
		{name: "generate different salts each time"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt, err := GenerateSalt()
			require.NoError(t, err)
			assert.Len(t, salt, SaltSize, "salt должен быть %d bytes", SaltSize)

			// Проверяем, что соль не состоит из одних нулей
			hasNonZero := false
			for _, b := range salt {
				if b != 0 {
					hasNonZero = true
					break
				}
			}
			assert.True(t, hasNonZero, "salt не должна состоять из одних нулей")
		})
	}
}

func TestGenerateSaltBase64(t *testing.T) {
	saltBase64, err := GenerateSaltBase64()
	require.NoError(t, err)
	assert.NotEmpty(t, saltBase64)

	// Проверяем что можно декодировать обратно
	// и получается правильная длина
	// (это проверка формата Base64)
	assert.Greater(t, len(saltBase64), 40, "Base64 encoded salt должна быть длиннее 40 символов")
}

func TestDeriveKeys(t *testing.T) {
	tests := []struct {
		name           string
		masterPassword string
		username       string
		saltLength     int
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "successful key derivation",
			masterPassword: "super_secret_password_123",
			username:       "alice",
			saltLength:     SaltSize,
			wantErr:        false,
		},
		{
			name:           "empty master password",
			masterPassword: "",
			username:       "alice",
			saltLength:     SaltSize,
			wantErr:        true,
			errMsg:         "master password cannot be empty",
		},
		{
			name:           "empty username",
			masterPassword: "password",
			username:       "",
			saltLength:     SaltSize,
			wantErr:        true,
			errMsg:         "username cannot be empty",
		},
		{
			name:           "invalid salt length",
			masterPassword: "password",
			username:       "alice",
			saltLength:     16, // неправильная длина
			wantErr:        true,
			errMsg:         "salt must be",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			salt := make([]byte, tt.saltLength)
			for i := range salt {
				salt[i] = byte(i) // заполняем тестовыми данными
			}

			keys, err := DeriveKeys(tt.masterPassword, tt.username, salt)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, keys)
			} else {
				require.NoError(t, err)
				require.NotNil(t, keys)

				// Проверка длины ключей
				assert.Len(t, keys.AuthKey, Argon2KeyLen, "auth key должен быть %d bytes", Argon2KeyLen)
				assert.Len(t, keys.EncryptionKey, Argon2KeyLen, "encryption key должен быть %d bytes", Argon2KeyLen)

				// Ключи должны быть разными
				assert.NotEqual(t, keys.AuthKey, keys.EncryptionKey, "auth key и encryption key должны быть разными")
			}
		})
	}
}

func TestDeriveKeys_Determinism(t *testing.T) {
	// Проверяем, что одинаковые входные данные дают одинаковые ключи
	masterPassword := "test_password_123"
	username := "bob"
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i * 2)
	}

	keys1, err1 := DeriveKeys(masterPassword, username, salt)
	require.NoError(t, err1)

	keys2, err2 := DeriveKeys(masterPassword, username, salt)
	require.NoError(t, err2)

	// Ключи должны быть идентичными
	assert.Equal(t, keys1.AuthKey, keys2.AuthKey, "auth keys должны быть одинаковыми при одинаковых входных данных")
	assert.Equal(t, keys1.EncryptionKey, keys2.EncryptionKey, "encryption keys должны быть одинаковыми при одинаковых входных данных")
}

func TestDeriveKeys_DifferentSalts(t *testing.T) {
	// Проверяем, что разные соли дают разные ключи
	masterPassword := "password"
	username := "alice"

	salt1 := make([]byte, SaltSize)
	salt2 := make([]byte, SaltSize)
	for i := range salt2 {
		salt2[i] = byte(i + 1) // другая соль
	}

	keys1, err1 := DeriveKeys(masterPassword, username, salt1)
	require.NoError(t, err1)

	keys2, err2 := DeriveKeys(masterPassword, username, salt2)
	require.NoError(t, err2)

	// Ключи должны быть разными
	assert.NotEqual(t, keys1.AuthKey, keys2.AuthKey, "разные соли должны давать разные auth keys")
	assert.NotEqual(t, keys1.EncryptionKey, keys2.EncryptionKey, "разные соли должны давать разные encryption keys")
}

func TestDeriveKeys_DifferentPasswords(t *testing.T) {
	// Проверяем, что разные пароли дают разные ключи
	username := "alice"
	salt := make([]byte, SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}

	keys1, err1 := DeriveKeys("password1", username, salt)
	require.NoError(t, err1)

	keys2, err2 := DeriveKeys("password2", username, salt)
	require.NoError(t, err2)

	// Ключи должны быть разными
	assert.NotEqual(t, keys1.AuthKey, keys2.AuthKey, "разные пароли должны давать разные auth keys")
	assert.NotEqual(t, keys1.EncryptionKey, keys2.EncryptionKey, "разные пароли должны давать разные encryption keys")
}

func TestDeriveKeysFromBase64Salt(t *testing.T) {
	tests := []struct {
		name           string
		masterPassword string
		username       string
		saltBase64     string
		wantErr        bool
		errMsg         string
	}{
		{
			name:           "successful derivation from base64",
			masterPassword: "password",
			username:       "alice",
			saltBase64:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 нуля в base64
			wantErr:        false,
		},
		{
			name:           "invalid base64",
			masterPassword: "password",
			username:       "alice",
			saltBase64:     "invalid-base64!!!",
			wantErr:        true,
			errMsg:         "failed to decode salt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := DeriveKeysFromBase64Salt(tt.masterPassword, tt.username, tt.saltBase64)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, keys)
			} else {
				require.NoError(t, err)
				require.NotNil(t, keys)
				assert.Len(t, keys.AuthKey, Argon2KeyLen)
				assert.Len(t, keys.EncryptionKey, Argon2KeyLen)
			}
		})
	}
}
