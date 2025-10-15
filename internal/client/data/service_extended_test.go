package data

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

// Tests for TextData

func TestTextData_FullCycle(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	userID := "user-123"

	// Create TextData
	originalText := &models.TextData{
		Name:    "Secret Note",
		Content: "This is a secret note with sensitive information",
		Metadata: models.Metadata{
			Tags:     []string{"secrets", "notes"},
			Category: "personal",
			Favorite: true,
		},
	}

	// Add TextData
	err := service.AddTextData(ctx, userID, originalText)
	require.NoError(t, err)
	assert.NotEmpty(t, originalText.ID)

	// Get TextData
	retrievedText, err := service.GetTextData(ctx, originalText.ID)
	require.NoError(t, err)
	require.NotNil(t, retrievedText)

	assert.Equal(t, originalText.ID, retrievedText.ID)
	assert.Equal(t, originalText.Name, retrievedText.Name)
	assert.Equal(t, originalText.Content, retrievedText.Content)
	assert.Equal(t, originalText.Metadata.Tags, retrievedText.Metadata.Tags)
	assert.Equal(t, originalText.Metadata.Category, retrievedText.Metadata.Category)
	assert.Equal(t, originalText.Metadata.Favorite, retrievedText.Metadata.Favorite)

	// List TextData
	textList, err := service.ListTextData(ctx)
	require.NoError(t, err)
	require.Len(t, textList, 1)
	assert.Equal(t, originalText.ID, textList[0].ID)

	// Delete TextData
	err = service.DeleteTextData(ctx, originalText.ID)
	require.NoError(t, err)

	// Verify entry is marked as deleted
	deletedEntry := mockStorage.entries[originalText.ID]
	assert.True(t, deletedEntry.Deleted)

	// Try to get deleted entry - should error
	_, err = service.GetTextData(ctx, originalText.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "text data is deleted")
}

func TestTextData_WrongType(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Create entry with wrong type
	entry := &models.CRDTEntry{
		ID:      "entry-123",
		Type:    models.DataTypeCredential, // Not text
		Deleted: false,
		Data:    []byte("encrypted-data"),
	}
	mockStorage.entries[entry.ID] = entry

	text, err := service.GetTextData(ctx, entry.ID)
	require.Error(t, err)
	assert.Nil(t, text)
	assert.Contains(t, err.Error(), "entry is not text data")
}

// Tests for BinaryData

func TestBinaryData_FullCycle(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	userID := "user-123"

	// Create BinaryData
	originalBinary := &models.BinaryData{
		Name:     "secret_document.pdf",
		MimeType: "application/pdf",
		Data:     []byte("binary file content here"),
		Metadata: models.Metadata{
			Tags:     []string{"documents", "work"},
			Category: "files",
		},
	}

	// Add BinaryData
	err := service.AddBinaryData(ctx, userID, originalBinary)
	require.NoError(t, err)
	assert.NotEmpty(t, originalBinary.ID)

	// Get BinaryData
	retrievedBinary, err := service.GetBinaryData(ctx, originalBinary.ID)
	require.NoError(t, err)
	require.NotNil(t, retrievedBinary)

	assert.Equal(t, originalBinary.ID, retrievedBinary.ID)
	assert.Equal(t, originalBinary.Name, retrievedBinary.Name)
	assert.Equal(t, originalBinary.MimeType, retrievedBinary.MimeType)
	assert.Equal(t, originalBinary.Data, retrievedBinary.Data)
	assert.Equal(t, originalBinary.Metadata.Tags, retrievedBinary.Metadata.Tags)

	// List BinaryData
	binaryList, err := service.ListBinaryData(ctx)
	require.NoError(t, err)
	require.Len(t, binaryList, 1)
	assert.Equal(t, originalBinary.ID, binaryList[0].ID)

	// Delete BinaryData
	err = service.DeleteBinaryData(ctx, originalBinary.ID)
	require.NoError(t, err)

	// Verify entry is marked as deleted
	deletedEntry := mockStorage.entries[originalBinary.ID]
	assert.True(t, deletedEntry.Deleted)
}

func TestBinaryData_WrongType(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Create entry with wrong type
	entry := &models.CRDTEntry{
		ID:      "entry-123",
		Type:    models.DataTypeCard, // Not binary
		Deleted: false,
		Data:    []byte("encrypted-data"),
	}
	mockStorage.entries[entry.ID] = entry

	binary, err := service.GetBinaryData(ctx, entry.ID)
	require.Error(t, err)
	assert.Nil(t, binary)
	assert.Contains(t, err.Error(), "entry is not binary data")
}

// Tests for CardData

func TestCardData_FullCycle(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	userID := "user-123"

	// Create CardData
	originalCard := &models.CardData{
		Name:   "Visa Gold",
		Number: "4111111111111111",
		Holder: "JOHN DOE",
		Expiry: "12/25",
		CVV:    "123",
		PIN:    "1234",
		Metadata: models.Metadata{
			Tags:     []string{"banking", "credit"},
			Category: "finance",
			Favorite: true,
		},
	}

	// Add CardData
	err := service.AddCardData(ctx, userID, originalCard)
	require.NoError(t, err)
	assert.NotEmpty(t, originalCard.ID)

	// Get CardData
	retrievedCard, err := service.GetCardData(ctx, originalCard.ID)
	require.NoError(t, err)
	require.NotNil(t, retrievedCard)

	assert.Equal(t, originalCard.ID, retrievedCard.ID)
	assert.Equal(t, originalCard.Name, retrievedCard.Name)
	assert.Equal(t, originalCard.Number, retrievedCard.Number)
	assert.Equal(t, originalCard.Holder, retrievedCard.Holder)
	assert.Equal(t, originalCard.Expiry, retrievedCard.Expiry)
	assert.Equal(t, originalCard.CVV, retrievedCard.CVV)
	assert.Equal(t, originalCard.PIN, retrievedCard.PIN)
	assert.Equal(t, originalCard.Metadata.Tags, retrievedCard.Metadata.Tags)
	assert.Equal(t, originalCard.Metadata.Favorite, retrievedCard.Metadata.Favorite)

	// List CardData
	cardList, err := service.ListCardData(ctx)
	require.NoError(t, err)
	require.Len(t, cardList, 1)
	assert.Equal(t, originalCard.ID, cardList[0].ID)

	// Delete CardData
	err = service.DeleteCardData(ctx, originalCard.ID)
	require.NoError(t, err)

	// Verify entry is marked as deleted
	deletedEntry := mockStorage.entries[originalCard.ID]
	assert.True(t, deletedEntry.Deleted)
}

func TestCardData_WrongType(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()

	// Create entry with wrong type
	entry := &models.CRDTEntry{
		ID:      "entry-123",
		Type:    models.DataTypeText, // Not card
		Deleted: false,
		Data:    []byte("encrypted-data"),
	}
	mockStorage.entries[entry.ID] = entry

	card, err := service.GetCardData(ctx, entry.ID)
	require.Error(t, err)
	assert.Nil(t, card)
	assert.Contains(t, err.Error(), "entry is not card data")
}

// Test encryption for all data types

func TestAllDataTypes_Encryption(t *testing.T) {
	mockStorage := newMockCRDTStorage()
	encKey := []byte("12345678901234567890123456789012")
	service := NewService(mockStorage, encKey, "test-node")

	ctx := context.Background()
	userID := "user-123"

	// Add all data types
	text := &models.TextData{Name: "Text", Content: "Content"}
	binary := &models.BinaryData{Name: "Binary", MimeType: "text/plain", Data: []byte("data")}
	card := &models.CardData{Name: "Card", Number: "1234", CVV: "123"}

	require.NoError(t, service.AddTextData(ctx, userID, text))
	require.NoError(t, service.AddBinaryData(ctx, userID, binary))
	require.NoError(t, service.AddCardData(ctx, userID, card))

	// Verify all entries are encrypted
	for _, entryID := range []string{text.ID, binary.ID, card.ID} {
		entry := mockStorage.entries[entryID]
		require.NotNil(t, entry)

		// Data should not be plaintext
		assert.NotContains(t, string(entry.Data), "Content")
		assert.NotContains(t, string(entry.Data), "1234")
		assert.NotContains(t, string(entry.Data), "123")

		// Should be able to decrypt with correct key
		decrypted, err := crypto.Decrypt(entry.Data, encKey)
		require.NoError(t, err)
		assert.NotEmpty(t, decrypted)

		// Should contain expected JSON structure
		var jsonCheck map[string]interface{}
		err = json.Unmarshal(decrypted, &jsonCheck)
		require.NoError(t, err)
	}
}
