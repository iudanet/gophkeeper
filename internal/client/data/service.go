package data

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

// service определяет интерфейс для клиентского data сервиса
type Service interface {
	AddCredential(ctx context.Context, userID, nodeID string, encryptionKey []byte, cred *models.Credential) error
	GetCredential(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error)
	ListCredentials(ctx context.Context, encryptionKey []byte) ([]*models.Credential, error)
	DeleteCredential(ctx context.Context, id, nodeID string) error

	AddTextData(ctx context.Context, userID, nodeID string, encryptionKey []byte, text *models.TextData) error
	GetTextData(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error)
	ListTextData(ctx context.Context, encryptionKey []byte) ([]*models.TextData, error)
	DeleteTextData(ctx context.Context, id, nodeID string) error

	AddBinaryData(ctx context.Context, userID, nodeID string, encryptionKey []byte, binary *models.BinaryData) error
	GetBinaryData(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error)
	ListBinaryData(ctx context.Context, encryptionKey []byte) ([]*models.BinaryData, error)
	DeleteBinaryData(ctx context.Context, id, nodeID string) error

	AddCardData(ctx context.Context, userID, nodeID string, encryptionKey []byte, card *models.CardData) error
	GetCardData(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error)
	ListCardData(ctx context.Context, encryptionKey []byte) ([]*models.CardData, error)
	DeleteCardData(ctx context.Context, id, nodeID string) error
}

// service handles client-side data operations with encryption
type service struct {
	crdtStorage storage.CRDTStorage
}

// Newservice creates a new data service
func NewService(crdtStorage storage.CRDTStorage) Service {
	return &service{
		crdtStorage: crdtStorage,
	}
}

// AddCredential adds a new credential to local storage
func (s *service) AddCredential(ctx context.Context, userID, nodeID string, encryptionKey []byte, cred *models.Credential) error {
	// Генерируем ID если не задан
	if cred.ID == "" {
		cred.ID = uuid.New().String()
	}

	// Сериализуем credential в JSON
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	// Шифруем данные
	encryptedData, err := crypto.Encrypt(credJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt credential: %w", err)
	}

	// Сериализуем metadata
	metadataJSON, err := json.Marshal(cred.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Шифруем metadata
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Создаем CRDT entry
	now := time.Now()
	entry := &models.CRDTEntry{
		ID:        cred.ID,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		NodeID:    nodeID,
		Data:      encryptedData,
		Metadata:  encryptedMetadata,
		Version:   1,
		Timestamp: now.Unix(),
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Сохраняем в локальное хранилище
	if err := s.crdtStorage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	return nil
}

// GetCredential retrieves and decrypts a credential by ID
func (s *service) GetCredential(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
	// Получаем CRDT entry
	entry, err := s.crdtStorage.GetEntry(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	// Проверяем тип
	if entry.Type != models.DataTypeCredential {
		return nil, fmt.Errorf("entry is not a credential, got type: %s", entry.Type)
	}

	// Проверяем что не удалено
	if entry.Deleted {
		return nil, fmt.Errorf("credential is deleted")
	}

	// Расшифровываем данные
	decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	// Десериализуем
	var cred models.Credential
	if err := json.Unmarshal(decryptedData, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	return &cred, nil
}

// ListCredentials returns all credentials for the user
func (s *service) ListCredentials(ctx context.Context, encryptionKey []byte) ([]*models.Credential, error) {
	// Получаем все активные entries типа credential
	entries, err := s.crdtStorage.GetEntriesByType(ctx, models.DataTypeCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}

	credentials := make([]*models.Credential, 0, len(entries))
	for _, entry := range entries {
		// Расшифровываем данные
		decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
		if err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		// Десериализуем
		var cred models.Credential
		if err := json.Unmarshal(decryptedData, &cred); err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		credentials = append(credentials, &cred)
	}

	return credentials, nil
}

// DeleteCredential marks credential as deleted (soft delete)
func (s *service) DeleteCredential(ctx context.Context, id, nodeID string) error {
	now := time.Now()
	if err := s.crdtStorage.DeleteEntry(ctx, id, now.Unix(), nodeID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	return nil
}

// AddTextData adds new text data to local storage
func (s *service) AddTextData(ctx context.Context, userID, nodeID string, encryptionKey []byte, text *models.TextData) error {
	// Генерируем ID если не задан
	if text.ID == "" {
		text.ID = uuid.New().String()
	}

	// Сериализуем text data в JSON
	textJSON, err := json.Marshal(text)
	if err != nil {
		return fmt.Errorf("failed to marshal text data: %w", err)
	}

	// Шифруем данные
	encryptedData, err := crypto.Encrypt(textJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt text data: %w", err)
	}

	// Сериализуем metadata
	metadataJSON, err := json.Marshal(text.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Шифруем metadata
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Создаем CRDT entry
	now := time.Now()
	entry := &models.CRDTEntry{
		ID:        text.ID,
		UserID:    userID,
		Type:      models.DataTypeText,
		NodeID:    nodeID,
		Data:      encryptedData,
		Metadata:  encryptedMetadata,
		Version:   1,
		Timestamp: now.Unix(),
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Сохраняем в локальное хранилище
	if err := s.crdtStorage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	return nil
}

// GetTextData retrieves and decrypts text data by ID
func (s *service) GetTextData(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
	// Получаем CRDT entry
	entry, err := s.crdtStorage.GetEntry(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	// Проверяем тип
	if entry.Type != models.DataTypeText {
		return nil, fmt.Errorf("entry is not text data, got type: %s", entry.Type)
	}

	// Проверяем что не удалено
	if entry.Deleted {
		return nil, fmt.Errorf("text data is deleted")
	}

	// Расшифровываем данные
	decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt text data: %w", err)
	}

	// Десериализуем
	var text models.TextData
	if err := json.Unmarshal(decryptedData, &text); err != nil {
		return nil, fmt.Errorf("failed to unmarshal text data: %w", err)
	}

	return &text, nil
}

// ListTextData returns all text data entries for the user
func (s *service) ListTextData(ctx context.Context, encryptionKey []byte) ([]*models.TextData, error) {
	// Получаем все активные entries типа text
	entries, err := s.crdtStorage.GetEntriesByType(ctx, models.DataTypeText)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}

	textData := make([]*models.TextData, 0, len(entries))
	for _, entry := range entries {
		// Расшифровываем данные
		decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
		if err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		// Десериализуем
		var text models.TextData
		if err := json.Unmarshal(decryptedData, &text); err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		textData = append(textData, &text)
	}

	return textData, nil
}

// DeleteTextData marks text data as deleted (soft delete)
func (s *service) DeleteTextData(ctx context.Context, id, nodeID string) error {
	now := time.Now()
	if err := s.crdtStorage.DeleteEntry(ctx, id, now.Unix(), nodeID); err != nil {
		return fmt.Errorf("failed to delete text data: %w", err)
	}
	return nil
}

// AddBinaryData adds new binary data to local storage
func (s *service) AddBinaryData(ctx context.Context, userID, nodeID string, encryptionKey []byte, binary *models.BinaryData) error {
	// Генерируем ID если не задан
	if binary.ID == "" {
		binary.ID = uuid.New().String()
	}

	// Сериализуем binary data в JSON
	binaryJSON, err := json.Marshal(binary)
	if err != nil {
		return fmt.Errorf("failed to marshal binary data: %w", err)
	}

	// Шифруем данные
	encryptedData, err := crypto.Encrypt(binaryJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt binary data: %w", err)
	}

	// Сериализуем metadata
	metadataJSON, err := json.Marshal(binary.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Шифруем metadata
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Создаем CRDT entry
	now := time.Now()
	entry := &models.CRDTEntry{
		ID:        binary.ID,
		UserID:    userID,
		Type:      models.DataTypeBinary,
		NodeID:    nodeID,
		Data:      encryptedData,
		Metadata:  encryptedMetadata,
		Version:   1,
		Timestamp: now.Unix(),
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Сохраняем в локальное хранилище
	if err := s.crdtStorage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	return nil
}

// GetBinaryData retrieves and decrypts binary data by ID
func (s *service) GetBinaryData(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
	// Получаем CRDT entry
	entry, err := s.crdtStorage.GetEntry(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	// Проверяем тип
	if entry.Type != models.DataTypeBinary {
		return nil, fmt.Errorf("entry is not binary data, got type: %s", entry.Type)
	}

	// Проверяем что не удалено
	if entry.Deleted {
		return nil, fmt.Errorf("binary data is deleted")
	}

	// Расшифровываем данные
	decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt binary data: %w", err)
	}

	// Десериализуем
	var binary models.BinaryData
	if err := json.Unmarshal(decryptedData, &binary); err != nil {
		return nil, fmt.Errorf("failed to unmarshal binary data: %w", err)
	}

	return &binary, nil
}

// ListBinaryData returns all binary data entries for the user
func (s *service) ListBinaryData(ctx context.Context, encryptionKey []byte) ([]*models.BinaryData, error) {
	// Получаем все активные entries типа binary
	entries, err := s.crdtStorage.GetEntriesByType(ctx, models.DataTypeBinary)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}

	binaryData := make([]*models.BinaryData, 0, len(entries))
	for _, entry := range entries {
		// Расшифровываем данные
		decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
		if err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		// Десериализуем
		var binary models.BinaryData
		if err := json.Unmarshal(decryptedData, &binary); err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		binaryData = append(binaryData, &binary)
	}

	return binaryData, nil
}

// DeleteBinaryData marks binary data as deleted (soft delete)
func (s *service) DeleteBinaryData(ctx context.Context, id, nodeID string) error {
	now := time.Now()
	if err := s.crdtStorage.DeleteEntry(ctx, id, now.Unix(), nodeID); err != nil {
		return fmt.Errorf("failed to delete binary data: %w", err)
	}
	return nil
}

// AddCardData adds new card data to local storage
func (s *service) AddCardData(ctx context.Context, userID, nodeID string, encryptionKey []byte, card *models.CardData) error {
	// Генерируем ID если не задан
	if card.ID == "" {
		card.ID = uuid.New().String()
	}

	// Сериализуем card data в JSON
	cardJSON, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("failed to marshal card data: %w", err)
	}

	// Шифруем данные
	encryptedData, err := crypto.Encrypt(cardJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt card data: %w", err)
	}

	// Сериализуем metadata
	metadataJSON, err := json.Marshal(card.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Шифруем metadata
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Создаем CRDT entry
	now := time.Now()
	entry := &models.CRDTEntry{
		ID:        card.ID,
		UserID:    userID,
		Type:      models.DataTypeCard,
		NodeID:    nodeID,
		Data:      encryptedData,
		Metadata:  encryptedMetadata,
		Version:   1,
		Timestamp: now.Unix(),
		Deleted:   false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Сохраняем в локальное хранилище
	if err := s.crdtStorage.SaveEntry(ctx, entry); err != nil {
		return fmt.Errorf("failed to save entry: %w", err)
	}

	return nil
}

// GetCardData retrieves and decrypts card data by ID
func (s *service) GetCardData(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
	// Получаем CRDT entry
	entry, err := s.crdtStorage.GetEntry(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}

	// Проверяем тип
	if entry.Type != models.DataTypeCard {
		return nil, fmt.Errorf("entry is not card data, got type: %s", entry.Type)
	}

	// Проверяем что не удалено
	if entry.Deleted {
		return nil, fmt.Errorf("card data is deleted")
	}

	// Расшифровываем данные
	decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt card data: %w", err)
	}

	// Десериализуем
	var card models.CardData
	if err := json.Unmarshal(decryptedData, &card); err != nil {
		return nil, fmt.Errorf("failed to unmarshal card data: %w", err)
	}

	return &card, nil
}

// ListCardData returns all card data entries for the user
func (s *service) ListCardData(ctx context.Context, encryptionKey []byte) ([]*models.CardData, error) {
	// Получаем все активные entries типа card
	entries, err := s.crdtStorage.GetEntriesByType(ctx, models.DataTypeCard)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}

	cardData := make([]*models.CardData, 0, len(entries))
	for _, entry := range entries {
		// Расшифровываем данные
		decryptedData, err := crypto.Decrypt(entry.Data, encryptionKey)
		if err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		// Десериализуем
		var card models.CardData
		if err := json.Unmarshal(decryptedData, &card); err != nil {
			// Пропускаем поврежденные записи
			continue
		}

		cardData = append(cardData, &card)
	}

	return cardData, nil
}

// DeleteCardData marks card data as deleted (soft delete)
func (s *service) DeleteCardData(ctx context.Context, id, nodeID string) error {
	now := time.Now()
	if err := s.crdtStorage.DeleteEntry(ctx, id, now.Unix(), nodeID); err != nil {
		return fmt.Errorf("failed to delete card data: %w", err)
	}
	return nil
}
