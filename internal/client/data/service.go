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

// Service handles client-side data operations with encryption
type Service struct {
	crdtStorage   storage.CRDTStorage
	encryptionKey []byte
	nodeID        string // Unique identifier for this client instance
}

// NewService creates a new data service
func NewService(crdtStorage storage.CRDTStorage, encryptionKey []byte, nodeID string) *Service {
	return &Service{
		crdtStorage:   crdtStorage,
		encryptionKey: encryptionKey,
		nodeID:        nodeID,
	}
}

// AddCredential adds a new credential to local storage
func (s *Service) AddCredential(ctx context.Context, userID string, cred *models.Credential) error {
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
	encryptedData, err := crypto.Encrypt(credJSON, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt credential: %w", err)
	}

	// Сериализуем metadata
	metadataJSON, err := json.Marshal(cred.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Шифруем metadata
	encryptedMetadata, err := crypto.Encrypt(metadataJSON, s.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	// Создаем CRDT entry
	now := time.Now()
	entry := &models.CRDTEntry{
		ID:        cred.ID,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		NodeID:    s.nodeID,
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
func (s *Service) GetCredential(ctx context.Context, id string) (*models.Credential, error) {
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
	decryptedData, err := crypto.Decrypt(entry.Data, s.encryptionKey)
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
func (s *Service) ListCredentials(ctx context.Context) ([]*models.Credential, error) {
	// Получаем все активные entries типа credential
	entries, err := s.crdtStorage.GetEntriesByType(ctx, models.DataTypeCredential)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}

	credentials := make([]*models.Credential, 0, len(entries))
	for _, entry := range entries {
		// Расшифровываем данные
		decryptedData, err := crypto.Decrypt(entry.Data, s.encryptionKey)
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
func (s *Service) DeleteCredential(ctx context.Context, id string) error {
	now := time.Now()
	if err := s.crdtStorage.DeleteEntry(ctx, id, now.Unix(), s.nodeID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}
	return nil
}
