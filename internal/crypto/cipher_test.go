package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	// Генерируем валидный ключ (32 bytes)
	validKey := make([]byte, 32)
	_, _ = rand.Read(validKey)

	tests := []struct {
		name      string
		errMsg    string
		plaintext []byte
		key       []byte
		wantErr   bool
	}{
		{
			name:      "successful encryption",
			plaintext: []byte("Hello, World!"),
			key:       validKey,
			wantErr:   false,
		},
		{
			name:      "encrypt longer text",
			plaintext: []byte("This is a longer text with multiple words and special characters: !@#$%^&*()"),
			key:       validKey,
			wantErr:   false,
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			key:       validKey,
			wantErr:   true,
			errMsg:    "plaintext cannot be empty",
		},
		{
			name:      "invalid key length - too short",
			plaintext: []byte("test"),
			key:       make([]byte, 16), // неправильная длина
			wantErr:   true,
			errMsg:    "encryption key must be 32 bytes",
		},
		{
			name:      "invalid key length - too long",
			plaintext: []byte("test"),
			key:       make([]byte, 64), // неправильная длина
			wantErr:   true,
			errMsg:    "encryption key must be 32 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext, tt.key)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, encrypted)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, encrypted)

				// Проверяем, что результат длиннее plaintext (nonce + ciphertext + auth_tag)
				// Минимум: NonceSize (12) + len(plaintext) + auth_tag (16)
				expectedMinLen := NonceSize + len(tt.plaintext) + 16
				assert.GreaterOrEqual(t, len(encrypted), expectedMinLen,
					"зашифрованные данные должны содержать nonce, ciphertext и auth_tag")

				// Проверяем, что зашифрованные данные отличаются от plaintext
				assert.NotEqual(t, tt.plaintext, encrypted[NonceSize:],
					"зашифрованные данные должны отличаться от plaintext")
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	// Генерируем валидный ключ
	validKey := make([]byte, 32)
	_, _ = rand.Read(validKey)

	// Создаем валидные зашифрованные данные
	plaintext := []byte("test message")
	validEncrypted, err := Encrypt(plaintext, validKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		errMsg    string
		encrypted []byte
		key       []byte
		wantErr   bool
	}{
		{
			name:      "successful decryption",
			encrypted: validEncrypted,
			key:       validKey,
			wantErr:   false,
		},
		{
			name:      "encrypted data too short",
			encrypted: make([]byte, 5), // меньше NonceSize
			key:       validKey,
			wantErr:   true,
			errMsg:    "encrypted data too short",
		},
		{
			name:      "invalid key length",
			encrypted: validEncrypted,
			key:       make([]byte, 16),
			wantErr:   true,
			errMsg:    "encryption key must be 32 bytes",
		},
		{
			name:      "wrong key",
			encrypted: validEncrypted,
			key:       make([]byte, 32), // другой ключ (все нули)
			wantErr:   true,
			errMsg:    "failed to decrypt",
		},
		{
			name:      "corrupted data",
			encrypted: append([]byte{}, validEncrypted[:len(validEncrypted)-1]...), // удалили последний байт
			key:       validKey,
			wantErr:   true,
			errMsg:    "failed to decrypt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := Decrypt(tt.encrypted, tt.key)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, decrypted)
			} else {
				require.NoError(t, err)
				assert.Equal(t, plaintext, decrypted,
					"расшифрованные данные должны совпадать с оригинальным plaintext")
			}
		})
	}
}

func TestEncryptDecrypt_Integration(t *testing.T) {
	// Интеграционный тест: шифруем и дешифруем различные данные
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	testCases := [][]byte{
		[]byte("Hello, World!"),
		[]byte("Привет, мир! 🌍"), // Unicode текст
		[]byte("12345"),
		[]byte(`{"username": "alice", "password": "secret123"}`), // JSON
		make([]byte, 1024),                                       // большой блок данных
	}

	// Заполняем последний тестовый случай случайными данными
	_, _ = rand.Read(testCases[len(testCases)-1])

	for i, plaintext := range testCases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			// Шифруем
			encrypted, err := Encrypt(plaintext, key)
			require.NoError(t, err)

			// Дешифруем
			decrypted, err := Decrypt(encrypted, key)
			require.NoError(t, err)

			// Проверяем, что получили оригинальные данные
			assert.Equal(t, plaintext, decrypted,
				"после шифрования и дешифрования должны получить оригинальные данные")
		})
	}
}

func TestEncrypt_Randomness(t *testing.T) {
	// Проверяем, что одинаковые данные шифруются по-разному (из-за случайного nonce)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := []byte("same data")

	encrypted1, err1 := Encrypt(plaintext, key)
	require.NoError(t, err1)

	encrypted2, err2 := Encrypt(plaintext, key)
	require.NoError(t, err2)

	// Зашифрованные данные должны быть разными
	assert.NotEqual(t, encrypted1, encrypted2,
		"одинаковые plaintext должны шифроваться по-разному из-за случайного nonce")

	// Но оба должны корректно дешифроваться
	decrypted1, _ := Decrypt(encrypted1, key)
	decrypted2, _ := Decrypt(encrypted2, key)
	assert.Equal(t, plaintext, decrypted1)
	assert.Equal(t, plaintext, decrypted2)
}

func TestEncryptToBase64(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	tests := []struct {
		name      string
		plaintext []byte
		key       []byte
		wantErr   bool
	}{
		{
			name:      "successful encryption to base64",
			plaintext: []byte("test data"),
			key:       key,
			wantErr:   false,
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			key:       key,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedBase64, err := EncryptToBase64(tt.plaintext, tt.key)

			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, encryptedBase64)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, encryptedBase64)

				// Проверяем, что это валидный Base64
				assert.Regexp(t, "^[A-Za-z0-9+/]+=*$", encryptedBase64,
					"результат должен быть валидным Base64")
			}
		})
	}
}

func TestDecryptFromBase64(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := []byte("test message")

	// Создаем валидные зашифрованные данные в Base64
	validEncryptedBase64, err := EncryptToBase64(plaintext, key)
	require.NoError(t, err)

	tests := []struct {
		name            string
		encryptedBase64 string
		errMsg          string
		key             []byte
		wantErr         bool
	}{
		{
			name:            "successful decryption from base64",
			encryptedBase64: validEncryptedBase64,
			key:             key,
			wantErr:         false,
		},
		{
			name:            "invalid base64",
			encryptedBase64: "invalid-base64!!!",
			key:             key,
			wantErr:         true,
			errMsg:          "failed to decode base64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := DecryptFromBase64(tt.encryptedBase64, tt.key)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, decrypted)
			} else {
				require.NoError(t, err)
				assert.Equal(t, plaintext, decrypted)
			}
		})
	}
}

func TestEncryptDecryptBase64_Integration(t *testing.T) {
	// Полный цикл: Encrypt -> Base64 -> Decrypt
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	plaintext := []byte("Hello, World!")

	// Шифруем в Base64
	encryptedBase64, err := EncryptToBase64(plaintext, key)
	require.NoError(t, err)

	// Дешифруем из Base64
	decrypted, err := DecryptFromBase64(encryptedBase64, key)
	require.NoError(t, err)

	// Проверяем результат
	assert.Equal(t, plaintext, decrypted)
}
