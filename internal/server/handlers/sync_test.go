package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/pkg/api"
)

// setupTestLogger creates a logger for testing
func setupTestLogger() *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors in tests
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	return slog.New(handler)
}

func TestSyncHandler_HandleSync_MethodNotAllowed(t *testing.T) {
	logger := setupTestLogger()
	storage := &mockDataStorage{}
	handler := NewSyncHandler(logger, storage)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/sync", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestSyncHandler_HandleSync_Unauthorized(t *testing.T) {
	logger := setupTestLogger()
	storage := &mockDataStorage{}
	handler := NewSyncHandler(logger, storage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil)
	// No user_id in context

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSyncHandler_HandleGetSync_Success(t *testing.T) {
	logger := setupTestLogger()

	// Prepare test data
	now := time.Now()
	entries := []*models.CRDTEntry{
		{
			ID:        "entry1",
			UserID:    "user123",
			Type:      models.DataTypeCredential,
			Data:      []byte("encrypted-data-1"),
			Metadata:  []byte("metadata-1"),
			Timestamp: 100,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "entry2",
			UserID:    "user123",
			Type:      models.DataTypeText,
			Data:      []byte("encrypted-data-2"),
			Metadata:  []byte("metadata-2"),
			Timestamp: 200,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	storage := &mockDataStorage{entries: entries}
	handler := NewSyncHandler(logger, storage)

	tests := []struct {
		name          string
		since         string
		expectedCount int
		expectedMax   int64
	}{
		{
			name:          "get all entries (since=0)",
			since:         "0",
			expectedCount: 2,
			expectedMax:   200,
		},
		{
			name:          "get entries since 100",
			since:         "100",
			expectedCount: 1,
			expectedMax:   200,
		},
		{
			name:          "get entries since 200",
			since:         "200",
			expectedCount: 0,
			expectedMax:   200,
		},
		{
			name:          "get all entries (no since param)",
			since:         "",
			expectedCount: 2,
			expectedMax:   200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/sync"
			if tt.since != "" {
				url += "?since=" + tt.since
			}

			req := httptest.NewRequest(http.MethodGet, url, nil)
			ctx := context.WithValue(req.Context(), UserIDKey, "user123")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()
			handler.HandleSync(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

			var response api.SyncResponse
			err := json.NewDecoder(w.Body).Decode(&response)
			require.NoError(t, err)

			assert.Len(t, response.Entries, tt.expectedCount)
			assert.Equal(t, tt.expectedMax, response.CurrentTimestamp)
			assert.Equal(t, 0, response.Conflicts)
		})
	}
}

func TestSyncHandler_HandleGetSync_InvalidSince(t *testing.T) {
	logger := setupTestLogger()
	storage := &mockDataStorage{}
	handler := NewSyncHandler(logger, storage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sync?since=invalid", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSyncHandler_HandlePostSync_Success(t *testing.T) {
	logger := setupTestLogger()
	now := time.Now()

	// Prepare server-side entries
	serverEntries := []*models.CRDTEntry{
		{
			ID:        "server-entry1",
			UserID:    "user123",
			Type:      models.DataTypeText,
			Data:      []byte("server-data-1"),
			Metadata:  []byte("server-metadata-1"),
			Timestamp: 150,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	storage := &mockDataStorage{entries: serverEntries}
	handler := NewSyncHandler(logger, storage)

	// Prepare client request
	clientEntries := []api.CRDTEntry{
		{
			ID:        "client-entry1",
			UserID:    "user123",
			DataType:  models.DataTypeCredential,
			Data:      []byte("client-data-1"),
			Metadata:  "client-metadata-1",
			Timestamp: 100,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "client-entry2",
			UserID:    "user123",
			DataType:  models.DataTypeCard,
			Data:      []byte("client-data-2"),
			Metadata:  "client-metadata-2",
			Timestamp: 200,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	syncRequest := api.SyncRequest{
		Since:   50,
		Entries: clientEntries,
	}

	body, err := json.Marshal(syncRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response api.SyncResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Should return all entries since timestamp 50 (including newly saved client entries)
	// server-entry1 (ts=150), client-entry1 (ts=100), client-entry2 (ts=200)
	assert.Len(t, response.Entries, 3)

	// Find entries by ID
	entryMap := make(map[string]api.CRDTEntry)
	for _, entry := range response.Entries {
		entryMap[entry.ID] = entry
	}

	assert.Contains(t, entryMap, "server-entry1")
	assert.Contains(t, entryMap, "client-entry1")
	assert.Contains(t, entryMap, "client-entry2")

	// Max timestamp should be 200 (from client-entry2)
	assert.Equal(t, int64(200), response.CurrentTimestamp)
	assert.Equal(t, 0, response.Conflicts)

	// Verify client entries were saved
	assert.Len(t, storage.savedEntries, 2)
}

func TestSyncHandler_HandlePostSync_Conflicts(t *testing.T) {
	logger := setupTestLogger()
	now := time.Now()

	// Prepare server-side entry with newer timestamp
	serverEntries := []*models.CRDTEntry{
		{
			ID:        "entry1",
			UserID:    "user123",
			Type:      models.DataTypeCredential,
			Data:      []byte("server-data-newer"),
			Metadata:  []byte("server-metadata"),
			Timestamp: 200, // Newer than client
			NodeID:    "server-node",
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	storage := &mockDataStorage{entries: serverEntries}
	handler := NewSyncHandler(logger, storage)

	// Client tries to send older version of same entry
	clientEntries := []api.CRDTEntry{
		{
			ID:        "entry1",
			UserID:    "user123",
			DataType:  models.DataTypeCredential,
			Data:      []byte("client-data-older"),
			Metadata:  "client-metadata",
			Timestamp: 100, // Older than server
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	syncRequest := api.SyncRequest{
		Since:   0,
		Entries: clientEntries,
	}

	body, err := json.Marshal(syncRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response api.SyncResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Should report 1 conflict (client's older entry was rejected)
	assert.Equal(t, 1, response.Conflicts)

	// Server entry should remain unchanged
	assert.Equal(t, []byte("server-data-newer"), serverEntries[0].Data)
}

func TestSyncHandler_HandlePostSync_UserIDMismatch(t *testing.T) {
	logger := setupTestLogger()
	storage := &mockDataStorage{}
	handler := NewSyncHandler(logger, storage)

	now := time.Now()
	clientEntries := []api.CRDTEntry{
		{
			ID:        "entry1",
			UserID:    "different-user", // Mismatch!
			DataType:  models.DataTypeCredential,
			Data:      []byte("data"),
			Metadata:  "metadata",
			Timestamp: 100,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	syncRequest := api.SyncRequest{
		Since:   0,
		Entries: clientEntries,
	}

	body, err := json.Marshal(syncRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestSyncHandler_HandlePostSync_InvalidJSON(t *testing.T) {
	logger := setupTestLogger()
	storage := &mockDataStorage{}
	handler := NewSyncHandler(logger, storage)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader([]byte("invalid json")))
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSyncHandler_HandlePostSync_EmptyEntries(t *testing.T) {
	logger := setupTestLogger()
	now := time.Now()

	serverEntries := []*models.CRDTEntry{
		{
			ID:        "server-entry1",
			UserID:    "user123",
			Type:      models.DataTypeText,
			Data:      []byte("server-data"),
			Metadata:  []byte("server-metadata"),
			Timestamp: 100,
			Deleted:   false,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	storage := &mockDataStorage{entries: serverEntries}
	handler := NewSyncHandler(logger, storage)

	// Client sends empty entries list
	syncRequest := api.SyncRequest{
		Since:   0,
		Entries: []api.CRDTEntry{},
	}

	body, err := json.Marshal(syncRequest)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sync", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), UserIDKey, "user123")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.HandleSync(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var response api.SyncResponse
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Should still return server entries
	assert.Len(t, response.Entries, 1)
	assert.Equal(t, 0, response.Conflicts)
	assert.Empty(t, storage.savedEntries)
}
