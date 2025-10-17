package data

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

// Константы для тестов
const (
	testUserID = "test-user-123"
	testNodeID = "test-node-456"
	testCredID = "cred-id-789"
	testTextID = "text-id-101"
	testBinID  = "bin-id-202"
	testCardID = "card-id-303"
)

var testEncryptionKey = []byte{
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
}

// ===== Tests for AddCredential =====

func TestService_AddCredential_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			// Проверяем, что entry корректно заполнен
			assert.Equal(t, testUserID, entry.UserID)
			assert.Equal(t, testNodeID, entry.NodeID)
			assert.Equal(t, models.DataTypeCredential, entry.Type)
			assert.NotEmpty(t, entry.Data)
			assert.NotEmpty(t, entry.Metadata)
			assert.False(t, entry.Deleted)
			assert.Equal(t, int64(1), entry.Version)
			return nil
		},
	}
	service := NewService(mockStorage)

	cred := &models.Credential{
		ID:       testCredID,
		Name:     "Test Credential",
		Login:    "testuser",
		Password: "testpass",
		URL:      "https://example.com",
		Metadata: models.Metadata{
			Tags: []string{"test", "example"},
		},
	}

	// Act
	err := service.AddCredential(context.Background(), testUserID, testNodeID, testEncryptionKey, cred)

	// Assert
	require.NoError(t, err)
}

func TestService_AddCredential_GeneratesID(t *testing.T) {
	// Arrange
	var savedEntry *models.CRDTEntry
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			savedEntry = entry
			return nil
		},
	}
	service := NewService(mockStorage)

	cred := &models.Credential{
		// ID не задан
		Name:     "Test",
		Login:    "test",
		Password: "pass",
	}

	// Act
	err := service.AddCredential(context.Background(), testUserID, testNodeID, testEncryptionKey, cred)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, cred.ID, "ID должен быть сгенерирован")
	assert.NotEmpty(t, savedEntry.ID, "Entry ID должен быть заполнен")
}

func TestService_AddCredential_SaveEntryError(t *testing.T) {
	// Arrange
	expectedErr := errors.New("storage error")
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			return expectedErr
		},
	}
	service := NewService(mockStorage)

	cred := &models.Credential{
		ID:       testCredID,
		Name:     "Test",
		Login:    "test",
		Password: "pass",
	}

	// Act
	err := service.AddCredential(context.Background(), testUserID, testNodeID, testEncryptionKey, cred)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save entry")
}

// ===== Tests for GetCredential =====

func TestService_GetCredential_Success(t *testing.T) {
	// Arrange
	originalCred := &models.Credential{
		ID:       testCredID,
		Name:     "GitHub",
		Login:    "myuser",
		Password: "mypass",
		URL:      "https://github.com",
		Metadata: models.Metadata{
			Tags:     []string{"work", "dev"},
			Category: "development",
		},
	}

	// Шифруем credential
	credJSON, err := json.Marshal(originalCred)
	require.NoError(t, err)
	encryptedData, err := crypto.Encrypt(credJSON, testEncryptionKey)
	require.NoError(t, err)

	// Шифруем metadata
	metadataJSON, err := json.Marshal(originalCred.Metadata)
	require.NoError(t, err)
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, testEncryptionKey)
	require.NoError(t, err)

	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			assert.Equal(t, testCredID, id)
			return &models.CRDTEntry{
				ID:       testCredID,
				Type:     models.DataTypeCredential,
				Data:     encryptedData,
				Metadata: encryptedMetadata,
				Deleted:  false,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCredential(context.Background(), testCredID, testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, originalCred.ID, result.ID)
	assert.Equal(t, originalCred.Name, result.Name)
	assert.Equal(t, originalCred.Login, result.Login)
	assert.Equal(t, originalCred.Password, result.Password)
	assert.Equal(t, originalCred.URL, result.URL)
	assert.Equal(t, originalCred.Metadata.Tags, result.Metadata.Tags)
}

func TestService_GetCredential_NotFound(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return nil, errors.New("entry not found")
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCredential(context.Background(), testCredID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get entry")
}

func TestService_GetCredential_WrongType(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:   testCredID,
				Type: models.DataTypeText, // Неверный тип
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCredential(context.Background(), testCredID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "entry is not a credential")
}

func TestService_GetCredential_Deleted(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testCredID,
				Type:    models.DataTypeCredential,
				Deleted: true, // Помечена как удаленная
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCredential(context.Background(), testCredID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "credential is deleted")
}

func TestService_GetCredential_DecryptionError(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testCredID,
				Type:    models.DataTypeCredential,
				Data:    []byte("invalid encrypted data"),
				Deleted: false,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCredential(context.Background(), testCredID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to decrypt credential")
}

// ===== Tests for ListCredentials =====

func TestService_ListCredentials_Success(t *testing.T) {
	// Arrange
	cred1 := &models.Credential{ID: "1", Name: "Cred1", Login: "user1", Password: "pass1"}
	cred2 := &models.Credential{ID: "2", Name: "Cred2", Login: "user2", Password: "pass2"}

	// Шифруем credentials
	cred1JSON, _ := json.Marshal(cred1)
	cred1Data, _ := crypto.Encrypt(cred1JSON, testEncryptionKey)

	cred2JSON, _ := json.Marshal(cred2)
	cred2Data, _ := crypto.Encrypt(cred2JSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			assert.Equal(t, models.DataTypeCredential, dataType)
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeCredential, Data: cred1Data, Deleted: false},
				{ID: "2", Type: models.DataTypeCredential, Data: cred2Data, Deleted: false},
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCredentials(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "Cred1", results[0].Name)
	assert.Equal(t, "Cred2", results[1].Name)
}

func TestService_ListCredentials_EmptyList(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			return []*models.CRDTEntry{}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCredentials(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestService_ListCredentials_StorageError(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			return nil, errors.New("storage error")
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCredentials(context.Background(), testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "failed to get entries")
}

func TestService_ListCredentials_SkipsCorruptedEntries(t *testing.T) {
	// Arrange
	validCred := &models.Credential{ID: "1", Name: "Valid", Login: "user", Password: "pass"}
	validCredJSON, _ := json.Marshal(validCred)
	validCredData, _ := crypto.Encrypt(validCredJSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeCredential, Data: validCredData, Deleted: false},
				{ID: "2", Type: models.DataTypeCredential, Data: []byte("corrupted"), Deleted: false}, // Поврежденная запись
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCredentials(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1, "Должна быть пропущена поврежденная запись")
	assert.Equal(t, "Valid", results[0].Name)
}

// ===== Tests for DeleteCredential =====

func TestService_DeleteCredential_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			assert.Equal(t, testCredID, id)
			assert.Equal(t, testNodeID, nodeID)
			assert.Greater(t, timestamp, int64(0))
			return nil
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteCredential(context.Background(), testCredID, testNodeID)

	// Assert
	require.NoError(t, err)
}

func TestService_DeleteCredential_StorageError(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			return errors.New("delete failed")
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteCredential(context.Background(), testCredID, testNodeID)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete credential")
}

// ===== Tests for TextData =====

func TestService_AddTextData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			assert.Equal(t, models.DataTypeText, entry.Type)
			return nil
		},
	}
	service := NewService(mockStorage)

	text := &models.TextData{
		ID:      testTextID,
		Name:    "My Note",
		Content: "Secret note content",
	}

	// Act
	err := service.AddTextData(context.Background(), testUserID, testNodeID, testEncryptionKey, text)

	// Assert
	require.NoError(t, err)
}

func TestService_GetTextData_Success(t *testing.T) {
	// Arrange
	originalText := &models.TextData{
		ID:      testTextID,
		Name:    "Recovery Phrase",
		Content: "word1 word2 word3",
	}

	textJSON, _ := json.Marshal(originalText)
	encryptedData, _ := crypto.Encrypt(textJSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testTextID,
				Type:    models.DataTypeText,
				Data:    encryptedData,
				Deleted: false,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetTextData(context.Background(), testTextID, testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, originalText.Name, result.Name)
	assert.Equal(t, originalText.Content, result.Content)
}

func TestService_GetTextData_WrongType(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:   testTextID,
				Type: models.DataTypeCredential, // Неверный тип
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetTextData(context.Background(), testTextID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "entry is not text data")
}

func TestService_ListTextData_Success(t *testing.T) {
	// Arrange
	text1 := &models.TextData{ID: "1", Name: "Note1", Content: "Content1"}
	text1JSON, _ := json.Marshal(text1)
	text1Data, _ := crypto.Encrypt(text1JSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			assert.Equal(t, models.DataTypeText, dataType)
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeText, Data: text1Data},
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListTextData(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "Note1", results[0].Name)
}

func TestService_DeleteTextData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			return nil
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteTextData(context.Background(), testTextID, testNodeID)

	// Assert
	require.NoError(t, err)
}

// ===== Tests for BinaryData =====

func TestService_AddBinaryData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			assert.Equal(t, models.DataTypeBinary, entry.Type)
			return nil
		},
	}
	service := NewService(mockStorage)

	binary := &models.BinaryData{
		ID:       testBinID,
		Name:     "photo.jpg",
		MimeType: "image/jpeg",
		Data:     []byte{0xFF, 0xD8, 0xFF}, // JPEG header
	}

	// Act
	err := service.AddBinaryData(context.Background(), testUserID, testNodeID, testEncryptionKey, binary)

	// Assert
	require.NoError(t, err)
}

func TestService_GetBinaryData_Success(t *testing.T) {
	// Arrange
	originalBinary := &models.BinaryData{
		ID:       testBinID,
		Name:     "document.pdf",
		MimeType: "application/pdf",
		Data:     []byte("PDF content"),
	}

	binaryJSON, _ := json.Marshal(originalBinary)
	encryptedData, _ := crypto.Encrypt(binaryJSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testBinID,
				Type:    models.DataTypeBinary,
				Data:    encryptedData,
				Deleted: false,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetBinaryData(context.Background(), testBinID, testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, originalBinary.Name, result.Name)
	assert.Equal(t, originalBinary.MimeType, result.MimeType)
	assert.Equal(t, originalBinary.Data, result.Data)
}

func TestService_GetBinaryData_Deleted(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testBinID,
				Type:    models.DataTypeBinary,
				Deleted: true,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetBinaryData(context.Background(), testBinID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "binary data is deleted")
}

func TestService_ListBinaryData_Success(t *testing.T) {
	// Arrange
	binary1 := &models.BinaryData{ID: "1", Name: "file1.txt", Data: []byte("data1")}
	binary1JSON, _ := json.Marshal(binary1)
	binary1Data, _ := crypto.Encrypt(binary1JSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			assert.Equal(t, models.DataTypeBinary, dataType)
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeBinary, Data: binary1Data},
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListBinaryData(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "file1.txt", results[0].Name)
}

func TestService_DeleteBinaryData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			return nil
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteBinaryData(context.Background(), testBinID, testNodeID)

	// Assert
	require.NoError(t, err)
}

// ===== Tests for CardData =====

func TestService_AddCardData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		SaveEntryFunc: func(ctx context.Context, entry *models.CRDTEntry) error {
			assert.Equal(t, models.DataTypeCard, entry.Type)
			return nil
		},
	}
	service := NewService(mockStorage)

	card := &models.CardData{
		ID:     testCardID,
		Name:   "Visa Gold",
		Number: "4111111111111111",
		Holder: "JOHN DOE",
		Expiry: "12/25",
		CVV:    "123",
		PIN:    "1234",
	}

	// Act
	err := service.AddCardData(context.Background(), testUserID, testNodeID, testEncryptionKey, card)

	// Assert
	require.NoError(t, err)
}

func TestService_GetCardData_Success(t *testing.T) {
	// Arrange
	originalCard := &models.CardData{
		ID:     testCardID,
		Name:   "MasterCard",
		Number: "5555555555554444",
		Holder: "JANE SMITH",
		Expiry: "06/26",
		CVV:    "456",
		PIN:    "5678",
	}

	cardJSON, _ := json.Marshal(originalCard)
	encryptedData, _ := crypto.Encrypt(cardJSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testCardID,
				Type:    models.DataTypeCard,
				Data:    encryptedData,
				Deleted: false,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCardData(context.Background(), testCardID, testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, originalCard.Name, result.Name)
	assert.Equal(t, originalCard.Number, result.Number)
	assert.Equal(t, originalCard.Holder, result.Holder)
	assert.Equal(t, originalCard.CVV, result.CVV)
}

func TestService_GetCardData_WrongType(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:   testCardID,
				Type: models.DataTypeBinary, // Неверный тип
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCardData(context.Background(), testCardID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "entry is not card data")
}

func TestService_GetCardData_Deleted(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		GetEntryFunc: func(ctx context.Context, id string) (*models.CRDTEntry, error) {
			return &models.CRDTEntry{
				ID:      testCardID,
				Type:    models.DataTypeCard,
				Deleted: true,
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	result, err := service.GetCardData(context.Background(), testCardID, testEncryptionKey)

	// Assert
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "card data is deleted")
}

func TestService_ListCardData_Success(t *testing.T) {
	// Arrange
	card1 := &models.CardData{ID: "1", Name: "Card1", Number: "4111111111111111"}
	card2 := &models.CardData{ID: "2", Name: "Card2", Number: "5555555555554444"}

	card1JSON, _ := json.Marshal(card1)
	card1Data, _ := crypto.Encrypt(card1JSON, testEncryptionKey)

	card2JSON, _ := json.Marshal(card2)
	card2Data, _ := crypto.Encrypt(card2JSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			assert.Equal(t, models.DataTypeCard, dataType)
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeCard, Data: card1Data},
				{ID: "2", Type: models.DataTypeCard, Data: card2Data},
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCardData(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 2)
	assert.Equal(t, "Card1", results[0].Name)
	assert.Equal(t, "Card2", results[1].Name)
}

func TestService_ListCardData_SkipsCorruptedEntries(t *testing.T) {
	// Arrange
	validCard := &models.CardData{ID: "1", Name: "ValidCard", Number: "4111111111111111"}
	validCardJSON, _ := json.Marshal(validCard)
	validCardData, _ := crypto.Encrypt(validCardJSON, testEncryptionKey)

	mockStorage := &storage.CRDTStorageMock{
		GetEntriesByTypeFunc: func(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
			return []*models.CRDTEntry{
				{ID: "1", Type: models.DataTypeCard, Data: validCardData},
				{ID: "2", Type: models.DataTypeCard, Data: []byte("corrupted data")}, // Поврежденная запись
			}, nil
		},
	}
	service := NewService(mockStorage)

	// Act
	results, err := service.ListCardData(context.Background(), testEncryptionKey)

	// Assert
	require.NoError(t, err)
	assert.Len(t, results, 1, "Поврежденная запись должна быть пропущена")
	assert.Equal(t, "ValidCard", results[0].Name)
}

func TestService_DeleteCardData_Success(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			assert.Equal(t, testCardID, id)
			return nil
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteCardData(context.Background(), testCardID, testNodeID)

	// Assert
	require.NoError(t, err)
}

func TestService_DeleteCardData_StorageError(t *testing.T) {
	// Arrange
	mockStorage := &storage.CRDTStorageMock{
		DeleteEntryFunc: func(ctx context.Context, id string, timestamp int64, nodeID string) error {
			return errors.New("delete failed")
		},
	}
	service := NewService(mockStorage)

	// Act
	err := service.DeleteCardData(context.Background(), testCardID, testNodeID)

	// Assert
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete card data")
}
