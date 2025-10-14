package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadata_JSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		metadata Metadata
	}{
		{
			name: "full metadata",
			metadata: Metadata{
				Tags:     []string{"work", "important"},
				Category: "banking",
				Favorite: true,
				Notes:    "My important note",
				CustomFields: map[string]string{
					"department": "IT",
					"project":    "GophKeeper",
				},
			},
		},
		{
			name: "minimal metadata",
			metadata: Metadata{
				Tags:         []string{},
				Category:     "",
				Favorite:     false,
				Notes:        "",
				CustomFields: map[string]string{},
			},
		},
		{
			name: "metadata with nil fields",
			metadata: Metadata{
				Tags:         nil,
				Category:     "",
				Favorite:     false,
				Notes:        "",
				CustomFields: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Сериализация
			data, err := json.Marshal(tt.metadata)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Десериализация
			var decoded Metadata
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Проверка равенства
			assert.Equal(t, tt.metadata.Category, decoded.Category)
			assert.Equal(t, tt.metadata.Favorite, decoded.Favorite)
			assert.Equal(t, tt.metadata.Notes, decoded.Notes)

			// Для nil slice/map JSON возвращает nil, а не пустой slice/map
			if tt.metadata.Tags != nil {
				assert.Equal(t, tt.metadata.Tags, decoded.Tags)
			}
			if tt.metadata.CustomFields != nil {
				assert.Equal(t, tt.metadata.CustomFields, decoded.CustomFields)
			}
		})
	}
}

func TestCredential_JSONSerialization(t *testing.T) {
	tests := []struct {
		name       string
		credential Credential
	}{
		{
			name: "full credential",
			credential: Credential{
				ID:       "cred-123",
				Name:     "GitHub",
				Login:    "alice",
				Password: "super_secret_password",
				URL:      "https://github.com",
				Notes:    "Work account",
				Metadata: Metadata{
					Tags:     []string{"work", "dev"},
					Category: "development",
					Favorite: true,
				},
			},
		},
		{
			name: "minimal credential",
			credential: Credential{
				ID:       "cred-456",
				Name:     "Test",
				Login:    "user",
				Password: "pass",
				URL:      "",
				Notes:    "",
				Metadata: Metadata{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Сериализация
			data, err := json.Marshal(tt.credential)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Десериализация
			var decoded Credential
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Проверка всех полей
			assert.Equal(t, tt.credential.ID, decoded.ID)
			assert.Equal(t, tt.credential.Name, decoded.Name)
			assert.Equal(t, tt.credential.Login, decoded.Login)
			assert.Equal(t, tt.credential.Password, decoded.Password)
			assert.Equal(t, tt.credential.URL, decoded.URL)
			assert.Equal(t, tt.credential.Notes, decoded.Notes)
		})
	}
}

func TestTextData_JSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		textData TextData
	}{
		{
			name: "full text data",
			textData: TextData{
				ID:      "text-123",
				Name:    "Secret Note",
				Content: "This is my secret note\nWith multiple lines\nAnd special chars: !@#$%",
				Metadata: Metadata{
					Tags:     []string{"personal", "secret"},
					Category: "notes",
					Favorite: false,
					Notes:    "Recovery seed phrase",
				},
			},
		},
		{
			name: "empty content",
			textData: TextData{
				ID:       "text-456",
				Name:     "Empty Note",
				Content:  "",
				Metadata: Metadata{},
			},
		},
		{
			name: "very long content",
			textData: TextData{
				ID:      "text-789",
				Name:    "Long Note",
				Content: string(make([]byte, 10000)), // 10KB текста
				Metadata: Metadata{
					Category: "large",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Сериализация
			data, err := json.Marshal(tt.textData)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Десериализация
			var decoded TextData
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Проверка всех полей
			assert.Equal(t, tt.textData.ID, decoded.ID)
			assert.Equal(t, tt.textData.Name, decoded.Name)
			assert.Equal(t, tt.textData.Content, decoded.Content)
			assert.Equal(t, len(tt.textData.Content), len(decoded.Content))
		})
	}
}

func TestBinaryData_JSONSerialization(t *testing.T) {
	tests := []struct {
		name       string
		binaryData BinaryData
	}{
		{
			name: "image file",
			binaryData: BinaryData{
				ID:       "bin-123",
				Name:     "passport.jpg",
				Data:     []byte{0xFF, 0xD8, 0xFF, 0xE0}, // JPEG header
				MimeType: "image/jpeg",
				Metadata: Metadata{
					Tags:     []string{"documents", "important"},
					Category: "identity",
					Favorite: true,
				},
			},
		},
		{
			name: "pdf document",
			binaryData: BinaryData{
				ID:       "bin-456",
				Name:     "contract.pdf",
				Data:     []byte{0x25, 0x50, 0x44, 0x46}, // PDF header
				MimeType: "application/pdf",
				Metadata: Metadata{
					Category: "legal",
				},
			},
		},
		{
			name: "empty binary",
			binaryData: BinaryData{
				ID:       "bin-789",
				Name:     "empty.bin",
				Data:     []byte{},
				MimeType: "application/octet-stream",
				Metadata: Metadata{},
			},
		},
		{
			name: "large binary file",
			binaryData: BinaryData{
				ID:       "bin-large",
				Name:     "video.mp4",
				Data:     make([]byte, 100000), // 100KB
				MimeType: "video/mp4",
				Metadata: Metadata{
					Category: "media",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Сериализация
			data, err := json.Marshal(tt.binaryData)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Десериализация
			var decoded BinaryData
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Проверка всех полей
			assert.Equal(t, tt.binaryData.ID, decoded.ID)
			assert.Equal(t, tt.binaryData.Name, decoded.Name)
			assert.Equal(t, tt.binaryData.Data, decoded.Data)
			assert.Equal(t, tt.binaryData.MimeType, decoded.MimeType)
			assert.Equal(t, len(tt.binaryData.Data), len(decoded.Data))
		})
	}
}

func TestCardData_JSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		cardData CardData
	}{
		{
			name: "full card data",
			cardData: CardData{
				ID:     "card-123",
				Name:   "Visa Gold",
				Number: "4111111111111111",
				Holder: "ALICE SMITH",
				Expiry: "12/25",
				CVV:    "123",
				PIN:    "1234",
				Metadata: Metadata{
					Tags:     []string{"banking", "primary"},
					Category: "payment",
					Favorite: true,
					Notes:    "Main credit card",
				},
			},
		},
		{
			name: "card without PIN",
			cardData: CardData{
				ID:     "card-456",
				Name:   "MasterCard",
				Number: "5500000000000004",
				Holder: "BOB JOHNSON",
				Expiry: "06/26",
				CVV:    "456",
				PIN:    "", // PIN опциональный
				Metadata: Metadata{
					Category: "payment",
				},
			},
		},
		{
			name: "minimal card data",
			cardData: CardData{
				ID:       "card-789",
				Name:     "Test Card",
				Number:   "0000000000000000",
				Holder:   "TEST USER",
				Expiry:   "01/99",
				CVV:      "000",
				PIN:      "",
				Metadata: Metadata{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Сериализация
			data, err := json.Marshal(tt.cardData)
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Десериализация
			var decoded CardData
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			// Проверка всех полей
			assert.Equal(t, tt.cardData.ID, decoded.ID)
			assert.Equal(t, tt.cardData.Name, decoded.Name)
			assert.Equal(t, tt.cardData.Number, decoded.Number)
			assert.Equal(t, tt.cardData.Holder, decoded.Holder)
			assert.Equal(t, tt.cardData.Expiry, decoded.Expiry)
			assert.Equal(t, tt.cardData.CVV, decoded.CVV)
			assert.Equal(t, tt.cardData.PIN, decoded.PIN)
		})
	}
}

func TestMetadata_EmptyFields(t *testing.T) {
	metadata := Metadata{
		Tags:         []string{},
		Category:     "",
		Favorite:     false,
		Notes:        "",
		CustomFields: map[string]string{},
	}

	assert.Empty(t, metadata.Tags)
	assert.Empty(t, metadata.Category)
	assert.False(t, metadata.Favorite)
	assert.Empty(t, metadata.Notes)
	assert.Empty(t, metadata.CustomFields)
}

func TestCredential_RequiredFields(t *testing.T) {
	cred := Credential{
		ID:       "test-id",
		Name:     "Test",
		Login:    "user",
		Password: "pass",
		Metadata: Metadata{},
	}

	// Обязательные поля заполнены
	assert.NotEmpty(t, cred.ID)
	assert.NotEmpty(t, cred.Name)
	assert.NotEmpty(t, cred.Login)
	assert.NotEmpty(t, cred.Password)

	// Опциональные поля могут быть пустыми
	assert.Empty(t, cred.URL)
	assert.Empty(t, cred.Notes)
}

func TestTextData_LongContent(t *testing.T) {
	// Создаем очень длинный текст
	longText := ""
	for i := 0; i < 10000; i++ {
		longText += "This is a long text. "
	}

	textData := TextData{
		ID:       "test-long",
		Name:     "Long Text",
		Content:  longText,
		Metadata: Metadata{},
	}

	// Проверяем что длинный текст корректно обрабатывается
	assert.NotEmpty(t, textData.Content)
	assert.Greater(t, len(textData.Content), 100000)

	// JSON сериализация работает
	data, err := json.Marshal(textData)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestBinaryData_EmptyData(t *testing.T) {
	binData := BinaryData{
		ID:       "test-empty",
		Name:     "empty.bin",
		Data:     []byte{},
		MimeType: "application/octet-stream",
		Metadata: Metadata{},
	}

	assert.Empty(t, binData.Data)
	assert.Equal(t, 0, len(binData.Data))
}

func TestCardData_Formats(t *testing.T) {
	tests := []struct {
		name        string
		cardNumber  string
		expiry      string
		cvv         string
		description string
	}{
		{
			name:        "standard 16-digit Visa",
			cardNumber:  "4111111111111111",
			expiry:      "12/25",
			cvv:         "123",
			description: "Standard Visa format",
		},
		{
			name:        "15-digit Amex",
			cardNumber:  "378282246310005",
			expiry:      "06/26",
			cvv:         "1234", // Amex has 4-digit CVV
			description: "American Express format",
		},
		{
			name:        "spaces in number",
			cardNumber:  "4111 1111 1111 1111",
			expiry:      "01/27",
			cvv:         "999",
			description: "Card number with spaces",
		},
		{
			name:        "dashes in number",
			cardNumber:  "4111-1111-1111-1111",
			expiry:      "03/28",
			cvv:         "111",
			description: "Card number with dashes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := CardData{
				ID:       "card-" + tt.name,
				Name:     tt.description,
				Number:   tt.cardNumber,
				Holder:   "TEST HOLDER",
				Expiry:   tt.expiry,
				CVV:      tt.cvv,
				Metadata: Metadata{},
			}

			// Проверяем что все форматы принимаются
			assert.Equal(t, tt.cardNumber, card.Number)
			assert.Equal(t, tt.expiry, card.Expiry)
			assert.Equal(t, tt.cvv, card.CVV)

			// JSON сериализация работает
			data, err := json.Marshal(card)
			require.NoError(t, err)
			assert.NotEmpty(t, data)
		})
	}
}

func TestAllDataTypes_UniqueIDs(t *testing.T) {
	// Создаем по одной записи каждого типа
	cred := Credential{ID: "cred-1"}
	text := TextData{ID: "text-1"}
	binary := BinaryData{ID: "bin-1"}
	card := CardData{ID: "card-1"}

	// ID должны быть уникальными между типами
	ids := []string{cred.ID, text.ID, binary.ID, card.ID}
	uniqueIDs := make(map[string]bool)
	for _, id := range ids {
		uniqueIDs[id] = true
	}

	assert.Equal(t, 4, len(uniqueIDs), "All IDs should be unique")
}
