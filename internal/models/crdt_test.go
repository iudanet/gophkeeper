package models

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCRDTEntry_IsNewerThan(t *testing.T) {

	tests := []struct {
		other    *CRDTEntry
		self     *CRDTEntry
		name     string
		expected bool
	}{
		{
			name:     "self timestamp greater",
			self:     &CRDTEntry{Timestamp: 101, NodeID: "nodeA"},
			other:    &CRDTEntry{Timestamp: 100, NodeID: "nodeA"},
			expected: true,
		},
		{
			name:     "self timestamp smaller",
			self:     &CRDTEntry{Timestamp: 90, NodeID: "nodeA"},
			other:    &CRDTEntry{Timestamp: 100, NodeID: "nodeA"},
			expected: false,
		},
		{
			name:     "timestamps equal, self NodeID greater lex",
			self:     &CRDTEntry{Timestamp: 100, NodeID: "nodeB"},
			other:    &CRDTEntry{Timestamp: 100, NodeID: "nodeA"},
			expected: true,
		},
		{
			name:     "timestamps equal, self NodeID lower lex",
			self:     &CRDTEntry{Timestamp: 100, NodeID: "nodeA"},
			other:    &CRDTEntry{Timestamp: 100, NodeID: "nodeB"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.self.IsNewerThan(tt.other)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCRDTEntry_Clone(t *testing.T) {
	now := time.Now()

	original := &CRDTEntry{
		CreatedAt: now,
		UpdatedAt: now.Add(time.Hour),
		ID:        "id-1",
		UserID:    "user-1",
		Type:      DataTypeCredential,
		NodeID:    "node1",
		Data:      []byte{1, 2, 3},
		Metadata:  []byte{4, 5, 6},
		Version:   42,
		Timestamp: 123456,
		Deleted:   false,
	}

	clone := original.Clone()

	// Проверяем равенство базовых полей
	assert.Equal(t, original.ID, clone.ID)
	assert.Equal(t, original.UserID, clone.UserID)
	assert.Equal(t, original.Type, clone.Type)
	assert.Equal(t, original.NodeID, clone.NodeID)
	assert.Equal(t, original.Version, clone.Version)
	assert.Equal(t, original.Timestamp, clone.Timestamp)
	assert.Equal(t, original.Deleted, clone.Deleted)
	assert.Equal(t, original.CreatedAt, clone.CreatedAt)
	assert.Equal(t, original.UpdatedAt, clone.UpdatedAt)

	// Проверяем, что срезы скопированы по значению, а не по ссылке (глубокая копия)
	assert.True(t, bytes.Equal(original.Data, clone.Data))
	assert.True(t, bytes.Equal(original.Metadata, clone.Metadata))

	// Модификация оригинала не должна влиять на клон
	original.Data[0] = 9
	original.Metadata[0] = 9
	assert.NotEqual(t, original.Data[0], clone.Data[0])
	assert.NotEqual(t, original.Metadata[0], clone.Metadata[0])
}
