package data

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

// mockCRDTStorage - простой hand-written mock для CRDTStorage интерфейса
type mockCRDTStorage struct {
	saveEntryErr         error
	getEntryErr          error
	getEntriesByTypeErr  error
	deleteEntryErr       error
	entries              map[string]*models.CRDTEntry
	lastSavedEntry       *models.CRDTEntry
	lastDeletedID        string
	lastDeletedNode      string
	lastDeletedTime      int64
	shouldReturnNotFound bool
}

func newMockCRDTStorage() *mockCRDTStorage {
	return &mockCRDTStorage{
		entries: make(map[string]*models.CRDTEntry),
	}
}

func (m *mockCRDTStorage) SaveEntry(ctx context.Context, entry *models.CRDTEntry) error {
	if m.saveEntryErr != nil {
		return m.saveEntryErr
	}
	m.lastSavedEntry = entry
	m.entries[entry.ID] = entry
	return nil
}

func (m *mockCRDTStorage) GetEntry(ctx context.Context, id string) (*models.CRDTEntry, error) {
	if m.getEntryErr != nil {
		return nil, m.getEntryErr
	}
	if m.shouldReturnNotFound {
		return nil, errors.New("entry not found")
	}
	entry, exists := m.entries[id]
	if !exists {
		return nil, errors.New("entry not found")
	}
	return entry, nil
}

func (m *mockCRDTStorage) GetAllEntries(ctx context.Context) ([]*models.CRDTEntry, error) {
	result := make([]*models.CRDTEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		result = append(result, entry)
	}
	return result, nil
}

func (m *mockCRDTStorage) GetEntriesAfterTimestamp(ctx context.Context, timestamp int64) ([]*models.CRDTEntry, error) {
	result := make([]*models.CRDTEntry, 0)
	for _, entry := range m.entries {
		if entry.Timestamp > timestamp {
			result = append(result, entry)
		}
	}
	return result, nil
}

func (m *mockCRDTStorage) GetActiveEntries(ctx context.Context) ([]*models.CRDTEntry, error) {
	result := make([]*models.CRDTEntry, 0)
	for _, entry := range m.entries {
		if !entry.Deleted {
			result = append(result, entry)
		}
	}
	return result, nil
}

func (m *mockCRDTStorage) GetEntriesByType(ctx context.Context, dataType string) ([]*models.CRDTEntry, error) {
	if m.getEntriesByTypeErr != nil {
		return nil, m.getEntriesByTypeErr
	}
	result := make([]*models.CRDTEntry, 0)
	for _, entry := range m.entries {
		if entry.Type == dataType && !entry.Deleted {
			result = append(result, entry)
		}
	}
	return result, nil
}

func (m *mockCRDTStorage) DeleteEntry(ctx context.Context, id string, timestamp int64, nodeID string) error {
	if m.deleteEntryErr != nil {
		return m.deleteEntryErr
	}
	m.lastDeletedID = id
	m.lastDeletedTime = timestamp
	m.lastDeletedNode = nodeID
	// Помечаем запись как удалённую
	if entry, exists := m.entries[id]; exists {
		entry.Deleted = true
		entry.Timestamp = timestamp
	}
	return nil
}

func (m *mockCRDTStorage) GetMaxTimestamp(ctx context.Context) (int64, error) {
	var maxTS int64
	for _, entry := range m.entries {
		if entry.Timestamp > maxTS {
			maxTS = entry.Timestamp
		}
	}
	return maxTS, nil
}

func (m *mockCRDTStorage) Clear(ctx context.Context) error {
	m.entries = make(map[string]*models.CRDTEntry)
	return nil
}

func TestNewService(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012") // 32 bytes
	nodeID := "test-node-id"

	service := NewService(mockStorage, encKey, nodeID)

	assert.NotNil(t, service)
	assert.Equal(t, mockStorage, service.crdtStorage)
	assert.Equal(t, encKey, service.encryptionKey)
	assert.Equal(t, nodeID, service.nodeID)
}

func TestAddCredential_Success(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	userID := "user-123"
	cred := &models.Credential{
		Name:     "GitHub",
		Login:    "testuser",
		Password: "secret123",
		URL:      "https://github.com",
		Notes:    "Work account",
		Metadata: models.Metadata{
			Tags:     []string{"work", "dev"},
			Category: "development",
			Favorite: true,
		},
	}

	err := service.AddCredential(ctx, userID, cred)
	require.NoError(t, err)

	// Проверяем что ID был сгенерирован
	assert.NotEmpty(t, cred.ID)

	// Проверяем что SaveEntry был вызван
	assert.NotNil(t, mockStorage.lastSavedEntry)
	savedEntry := mockStorage.lastSavedEntry

	// Проверяем поля entry
	assert.Equal(t, cred.ID, savedEntry.ID)
	assert.Equal(t, userID, savedEntry.UserID)
	assert.Equal(t, models.DataTypeCredential, savedEntry.Type)
	assert.Equal(t, nodeID, savedEntry.NodeID)
	assert.Equal(t, int64(1), savedEntry.Version)
	assert.False(t, savedEntry.Deleted)
	assert.NotZero(t, savedEntry.Timestamp)
	assert.NotEmpty(t, savedEntry.Data)
	assert.NotEmpty(t, savedEntry.Metadata)

	// Проверяем что данные зашифрованы (можем расшифровать)
	decryptedData, err := crypto.Decrypt(savedEntry.Data, encKey)
	require.NoError(t, err)

	var decryptedCred models.Credential
	err = json.Unmarshal(decryptedData, &decryptedCred)
	require.NoError(t, err)

	assert.Equal(t, cred.Name, decryptedCred.Name)
	assert.Equal(t, cred.Login, decryptedCred.Login)
	assert.Equal(t, cred.Password, decryptedCred.Password)
	assert.Equal(t, cred.URL, decryptedCred.URL)
	assert.Equal(t, cred.Notes, decryptedCred.Notes)

	// Проверяем metadata
	decryptedMetadata, err := crypto.Decrypt(savedEntry.Metadata, encKey)
	require.NoError(t, err)

	var metadata models.Metadata
	err = json.Unmarshal(decryptedMetadata, &metadata)
	require.NoError(t, err)

	assert.Equal(t, cred.Metadata.Tags, metadata.Tags)
	assert.Equal(t, cred.Metadata.Category, metadata.Category)
	assert.Equal(t, cred.Metadata.Favorite, metadata.Favorite)
}

func TestAddCredential_WithExistingID(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	existingID := "existing-id-123"
	cred := &models.Credential{
		ID:       existingID,
		Name:     "Test",
		Login:    "user",
		Password: "pass",
	}

	err := service.AddCredential(ctx, "user-123", cred)
	require.NoError(t, err)

	// Проверяем что ID не изменился
	assert.Equal(t, existingID, cred.ID)
	assert.Equal(t, existingID, mockStorage.lastSavedEntry.ID)
}

func TestAddCredential_StorageError(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	mockStorage.saveEntryErr = errors.New("storage error")
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	cred := &models.Credential{
		Name:     "Test",
		Login:    "user",
		Password: "pass",
	}

	err := service.AddCredential(ctx, "user-123", cred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save entry")
}

func TestGetCredential_Success(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()

	// Подготавливаем тестовый credential
	originalCred := &models.Credential{
		ID:       "cred-123",
		Name:     "Gmail",
		Login:    "test@example.com",
		Password: "password123",
		URL:      "https://gmail.com",
		Notes:    "Personal email",
		Metadata: models.Metadata{
			Tags:     []string{"email", "personal"},
			Category: "communication",
			Favorite: false,
		},
	}

	// Шифруем credential
	credJSON, err := json.Marshal(originalCred)
	require.NoError(t, err)
	encryptedData, err := crypto.Encrypt(credJSON, encKey)
	require.NoError(t, err)

	// Шифруем metadata
	metadataJSON, err := json.Marshal(originalCred.Metadata)
	require.NoError(t, err)
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, encKey)
	require.NoError(t, err)

	// Создаём CRDT entry
	entry := &models.CRDTEntry{
		ID:        originalCred.ID,
		UserID:    "user-123",
		Type:      models.DataTypeCredential,
		NodeID:    nodeID,
		Data:      encryptedData,
		Metadata:  encryptedMetadata,
		Version:   1,
		Timestamp: time.Now().Unix(),
		Deleted:   false,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockStorage.entries[entry.ID] = entry

	// Получаем credential
	retrievedCred, err := service.GetCredential(ctx, originalCred.ID)
	require.NoError(t, err)
	require.NotNil(t, retrievedCred)

	// Проверяем все поля
	assert.Equal(t, originalCred.ID, retrievedCred.ID)
	assert.Equal(t, originalCred.Name, retrievedCred.Name)
	assert.Equal(t, originalCred.Login, retrievedCred.Login)
	assert.Equal(t, originalCred.Password, retrievedCred.Password)
	assert.Equal(t, originalCred.URL, retrievedCred.URL)
	assert.Equal(t, originalCred.Notes, retrievedCred.Notes)
	assert.Equal(t, originalCred.Metadata.Tags, retrievedCred.Metadata.Tags)
	assert.Equal(t, originalCred.Metadata.Category, retrievedCred.Metadata.Category)
	assert.Equal(t, originalCred.Metadata.Favorite, retrievedCred.Metadata.Favorite)
}

func TestGetCredential_NotFound(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	mockStorage.shouldReturnNotFound = true
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	cred, err := service.GetCredential(ctx, "non-existent-id")
	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "failed to get entry")
}

func TestGetCredential_WrongType(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Создаём entry с неправильным типом
	entry := &models.CRDTEntry{
		ID:      "entry-123",
		Type:    "text", // Не credential
		Deleted: false,
		Data:    []byte("encrypted-data"),
	}
	mockStorage.entries[entry.ID] = entry

	cred, err := service.GetCredential(ctx, entry.ID)
	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "entry is not a credential")
}

func TestGetCredential_Deleted(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Создаём удалённый entry
	entry := &models.CRDTEntry{
		ID:      "entry-123",
		Type:    models.DataTypeCredential,
		Deleted: true,
		Data:    []byte("encrypted-data"),
	}
	mockStorage.entries[entry.ID] = entry

	cred, err := service.GetCredential(ctx, entry.ID)
	require.Error(t, err)
	assert.Nil(t, cred)
	assert.Contains(t, err.Error(), "credential is deleted")
}

func TestGetCredential_DecryptionError(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	wrongKey := []byte("00000000000000000000000000000000")
	service := NewService(mockStorage, wrongKey, "test-node") // Неправильный ключ

	ctx := context.Background()

	// Создаём credential зашифрованный правильным ключом
	cred := &models.Credential{
		ID:       "cred-123",
		Name:     "Test",
		Login:    "user",
		Password: "pass",
	}
	credJSON, err := json.Marshal(cred)
	require.NoError(t, err)
	encryptedData, err := crypto.Encrypt(credJSON, encKey) // Правильный ключ
	require.NoError(t, err)

	entry := &models.CRDTEntry{
		ID:      cred.ID,
		Type:    models.DataTypeCredential,
		Deleted: false,
		Data:    encryptedData,
	}
	mockStorage.entries[entry.ID] = entry

	// Пытаемся получить с неправильным ключом
	retrievedCred, err := service.GetCredential(ctx, cred.ID)
	require.Error(t, err)
	assert.Nil(t, retrievedCred)
	assert.Contains(t, err.Error(), "failed to decrypt credential")
}

func TestListCredentials_Success(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Создаём несколько credentials
	creds := []*models.Credential{
		{
			ID:       "cred-1",
			Name:     "GitHub",
			Login:    "user1",
			Password: "pass1",
			Metadata: models.Metadata{Tags: []string{"work"}},
		},
		{
			ID:       "cred-2",
			Name:     "Gmail",
			Login:    "user2",
			Password: "pass2",
			Metadata: models.Metadata{Tags: []string{"personal"}},
		},
		{
			ID:       "cred-3",
			Name:     "AWS",
			Login:    "user3",
			Password: "pass3",
			Metadata: models.Metadata{Favorite: true},
		},
	}

	// Шифруем и сохраняем credentials
	for _, cred := range creds {
		credJSON, err := json.Marshal(cred)
		require.NoError(t, err)
		encryptedData, err := crypto.Encrypt(credJSON, encKey)
		require.NoError(t, err)

		entry := &models.CRDTEntry{
			ID:      cred.ID,
			Type:    models.DataTypeCredential,
			Deleted: false,
			Data:    encryptedData,
		}
		mockStorage.entries[entry.ID] = entry
	}

	// Получаем список credentials
	retrievedCreds, err := service.ListCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, retrievedCreds)
	assert.Len(t, retrievedCreds, 3)

	// Проверяем что все credentials получены
	credMap := make(map[string]*models.Credential)
	for _, cred := range retrievedCreds {
		credMap[cred.ID] = cred
	}

	for _, originalCred := range creds {
		retrievedCred, exists := credMap[originalCred.ID]
		require.True(t, exists, "credential %s not found", originalCred.ID)
		assert.Equal(t, originalCred.Name, retrievedCred.Name)
		assert.Equal(t, originalCred.Login, retrievedCred.Login)
		assert.Equal(t, originalCred.Password, retrievedCred.Password)
	}
}

func TestListCredentials_Empty(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Не добавляем никаких credentials
	creds, err := service.ListCredentials(ctx)
	require.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Len(t, creds, 0)
}

func TestListCredentials_SkipsCorruptedEntries(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Добавляем валидный credential
	validCred := &models.Credential{
		ID:       "cred-valid",
		Name:     "Valid",
		Login:    "user",
		Password: "pass",
	}
	credJSON, err := json.Marshal(validCred)
	require.NoError(t, err)
	encryptedData, err := crypto.Encrypt(credJSON, encKey)
	require.NoError(t, err)

	validEntry := &models.CRDTEntry{
		ID:      validCred.ID,
		Type:    models.DataTypeCredential,
		Deleted: false,
		Data:    encryptedData,
	}
	mockStorage.entries[validEntry.ID] = validEntry

	// Добавляем поврежденный entry (невалидные зашифрованные данные)
	corruptedEntry := &models.CRDTEntry{
		ID:      "cred-corrupted",
		Type:    models.DataTypeCredential,
		Deleted: false,
		Data:    []byte("corrupted-data-not-encrypted"),
	}
	mockStorage.entries[corruptedEntry.ID] = corruptedEntry

	// Получаем список - должен вернуть только валидный
	creds, err := service.ListCredentials(ctx)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, validCred.ID, creds[0].ID)
	assert.Equal(t, validCred.Name, creds[0].Name)
}

func TestListCredentials_StorageError(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	mockStorage.getEntriesByTypeErr = errors.New("storage error")
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	creds, err := service.ListCredentials(ctx)
	require.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "failed to get entries")
}

func TestDeleteCredential_Success(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	credID := "cred-123"

	// Создаём entry для удаления
	entry := &models.CRDTEntry{
		ID:      credID,
		Type:    models.DataTypeCredential,
		Deleted: false,
	}
	mockStorage.entries[entry.ID] = entry

	// Удаляем credential
	beforeDelete := time.Now().Unix()
	err := service.DeleteCredential(ctx, credID)
	afterDelete := time.Now().Unix()

	require.NoError(t, err)

	// Проверяем что DeleteEntry был вызван с правильными параметрами
	assert.Equal(t, credID, mockStorage.lastDeletedID)
	assert.Equal(t, nodeID, mockStorage.lastDeletedNode)
	assert.GreaterOrEqual(t, mockStorage.lastDeletedTime, beforeDelete)
	assert.LessOrEqual(t, mockStorage.lastDeletedTime, afterDelete)

	// Проверяем что entry помечен как удалённый
	deletedEntry := mockStorage.entries[credID]
	assert.True(t, deletedEntry.Deleted)
}

func TestDeleteCredential_StorageError(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	mockStorage.deleteEntryErr = errors.New("delete error")
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	err := service.DeleteCredential(ctx, "cred-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete credential")
}

func TestEncryptionDecryption_FullCycle(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	userID := "user-123"

	// Создаём credential с различными символами и юникодом
	originalCred := &models.Credential{
		Name:     "测试 Test тест",
		Login:    "user@тест.рф",
		Password: "пароль!@#$%^&*()_+{}[]|\\:\";<>?,./",
		URL:      "https://例え.jp/测试/тест",
		Notes:    "Multiline\nnotes\nwith special chars: \t\r\n",
		Metadata: models.Metadata{
			Tags:         []string{"tag1", "тег2", "标签3"},
			Category:     "категория",
			Notes:        "заметки 📝",
			Favorite:     true,
			CustomFields: map[string]string{"key1": "value1", "ключ2": "значение2"},
		},
	}

	// Добавляем credential (шифруем)
	err := service.AddCredential(ctx, userID, originalCred)
	require.NoError(t, err)

	// Получаем credential (расшифровываем)
	retrievedCred, err := service.GetCredential(ctx, originalCred.ID)
	require.NoError(t, err)

	// Проверяем что все данные идентичны после цикла шифрования-дешифрования
	assert.Equal(t, originalCred.ID, retrievedCred.ID)
	assert.Equal(t, originalCred.Name, retrievedCred.Name)
	assert.Equal(t, originalCred.Login, retrievedCred.Login)
	assert.Equal(t, originalCred.Password, retrievedCred.Password)
	assert.Equal(t, originalCred.URL, retrievedCred.URL)
	assert.Equal(t, originalCred.Notes, retrievedCred.Notes)
	assert.Equal(t, originalCred.Metadata.Tags, retrievedCred.Metadata.Tags)
	assert.Equal(t, originalCred.Metadata.Category, retrievedCred.Metadata.Category)
	assert.Equal(t, originalCred.Metadata.Notes, retrievedCred.Metadata.Notes)
	assert.Equal(t, originalCred.Metadata.Favorite, retrievedCred.Metadata.Favorite)
	assert.Equal(t, originalCred.Metadata.CustomFields, retrievedCred.Metadata.CustomFields)
}

func TestService_DifferentEncryptionKeys(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey1 := []byte("12345678901234567890123456789012")
	encKey2 := []byte("abcdefghijklmnopqrstuvwxyz123456")

	service1 := NewService(mockStorage, encKey1, "node-1")
	service2 := NewService(mockStorage, encKey2, "node-2")

	ctx := context.Background()

	// Добавляем credential с первым ключом
	cred := &models.Credential{
		ID:       "cred-123",
		Name:     "Test",
		Login:    "user",
		Password: "secret",
	}

	err := service1.AddCredential(ctx, "user-123", cred)
	require.NoError(t, err)

	// Пытаемся получить со вторым ключом - должна быть ошибка
	retrievedCred, err := service2.GetCredential(ctx, cred.ID)
	require.Error(t, err)
	assert.Nil(t, retrievedCred)
	assert.Contains(t, err.Error(), "failed to decrypt credential")
}

// TestAddCredential_UserIDInCRDTEntry проверяет что UserID правильно сохраняется в CRDT entry
// Это регрессионный тест для бага, где использовался Username вместо UserID
func TestAddCredential_UserIDInCRDTEntry(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	// UserID должен быть UUID формат, а не username
	userID := "2afeb7d9-7aea-47af-a96e-bbfbf3b3a5bf"

	cred := &models.Credential{
		Name:     "GitHub",
		Login:    "testuser",
		Password: "secret123",
	}

	err := service.AddCredential(ctx, userID, cred)
	require.NoError(t, err)

	// Проверяем что в CRDT entry сохранен именно UserID (UUID), а не username
	assert.NotNil(t, mockStorage.lastSavedEntry)
	assert.Equal(t, userID, mockStorage.lastSavedEntry.UserID)
	assert.Contains(t, mockStorage.lastSavedEntry.UserID, "-")        // UUID должен содержать дефисы
	assert.NotEqual(t, "testuser", mockStorage.lastSavedEntry.UserID) // НЕ username
}

// TestAddTextData_UserIDInCRDTEntry проверяет что UserID правильно сохраняется для text data
func TestAddTextData_UserIDInCRDTEntry(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	userID := "3b7ec8d1-8bfa-48af-b97e-ccfcf4c4b6cf"

	textData := &models.TextData{
		Name:    "Notes",
		Content: "My secret notes",
	}

	err := service.AddTextData(ctx, userID, textData)
	require.NoError(t, err)

	// Проверяем что UserID сохранен в CRDT entry
	assert.NotNil(t, mockStorage.lastSavedEntry)
	assert.Equal(t, userID, mockStorage.lastSavedEntry.UserID)
	assert.Equal(t, models.DataTypeText, mockStorage.lastSavedEntry.Type)
	assert.Contains(t, mockStorage.lastSavedEntry.UserID, "-") // UUID формат
}

// TestAddBinaryData_UserIDInCRDTEntry проверяет что UserID правильно сохраняется для binary data
func TestAddBinaryData_UserIDInCRDTEntry(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	userID := "4c8fd9e2-9cga-59bg-c08f-ddfdf5d5c7dg"

	binaryData := &models.BinaryData{
		Name:     "document.pdf",
		MimeType: "application/pdf",
		Data:     []byte("fake pdf content"),
	}

	err := service.AddBinaryData(ctx, userID, binaryData)
	require.NoError(t, err)

	// Проверяем что UserID сохранен в CRDT entry
	assert.NotNil(t, mockStorage.lastSavedEntry)
	assert.Equal(t, userID, mockStorage.lastSavedEntry.UserID)
	assert.Equal(t, models.DataTypeBinary, mockStorage.lastSavedEntry.Type)
	assert.Contains(t, mockStorage.lastSavedEntry.UserID, "-") // UUID формат
}

// TestAddCardData_UserIDInCRDTEntry проверяет что UserID правильно сохраняется для card data
func TestAddCardData_UserIDInCRDTEntry(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	nodeID := "test-node-id"
	service := NewService(mockStorage, encKey, nodeID)

	ctx := context.Background()
	userID := "5d9ge0f3-0dha-60ch-d19g-eegeg6e6d8eh"

	cardData := &models.CardData{
		Name:   "Bank Card",
		Number: "4111111111111111",
		Holder: "John Doe",
		CVV:    "123",
		Expiry: "12/25",
	}

	err := service.AddCardData(ctx, userID, cardData)
	require.NoError(t, err)

	// Проверяем что UserID сохранен в CRDT entry
	assert.NotNil(t, mockStorage.lastSavedEntry)
	assert.Equal(t, userID, mockStorage.lastSavedEntry.UserID)
	assert.Equal(t, models.DataTypeCard, mockStorage.lastSavedEntry.Type)
	assert.Contains(t, mockStorage.lastSavedEntry.UserID, "-") // UUID формат
}

// TestAllDataTypes_UserIDNotUsername проверяет что все типы используют UserID а не Username
// Комплексный регрессионный тест для бага из add.go
func TestAllDataTypes_UserIDNotUsername(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Эмулируем реальную ситуацию: есть username и UserID
	username := "test2"
	userID := "2afeb7d9-7aea-47af-a96e-bbfbf3b3a5bf" // UUID из реального бага

	tests := []struct {
		addFunc  func() error
		name     string
		dataType string
	}{
		{
			name:     "Credential",
			dataType: models.DataTypeCredential,
			addFunc: func() error {
				return service.AddCredential(ctx, userID, &models.Credential{
					Name:     "Test",
					Login:    "user",
					Password: "pass",
				})
			},
		},
		{
			name:     "TextData",
			dataType: models.DataTypeText,
			addFunc: func() error {
				return service.AddTextData(ctx, userID, &models.TextData{
					Name:    "Note",
					Content: "content",
				})
			},
		},
		{
			name:     "BinaryData",
			dataType: models.DataTypeBinary,
			addFunc: func() error {
				return service.AddBinaryData(ctx, userID, &models.BinaryData{
					Name:     "file.txt",
					MimeType: "text/plain",
					Data:     []byte("data"),
				})
			},
		},
		{
			name:     "CardData",
			dataType: models.DataTypeCard,
			addFunc: func() error {
				return service.AddCardData(ctx, userID, &models.CardData{
					Name:   "Card",
					Number: "4111111111111111",
					Holder: "John Doe",
					CVV:    "123",
					Expiry: "12/25",
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем mock перед каждым тестом
			mockStorage.lastSavedEntry = nil

			err := tt.addFunc()
			require.NoError(t, err)

			// КРИТИЧЕСКАЯ ПРОВЕРКА: UserID должен быть UUID, а НЕ username
			require.NotNil(t, mockStorage.lastSavedEntry)
			assert.Equal(t, userID, mockStorage.lastSavedEntry.UserID,
				"Expected UserID (UUID) but got something else for %s", tt.dataType)
			assert.NotEqual(t, username, mockStorage.lastSavedEntry.UserID,
				"UserID should NOT be username for %s", tt.dataType)
			assert.Contains(t, mockStorage.lastSavedEntry.UserID, "-",
				"UserID should be in UUID format (with dashes) for %s", tt.dataType)
			assert.Equal(t, tt.dataType, mockStorage.lastSavedEntry.Type)
		})
	}
}
