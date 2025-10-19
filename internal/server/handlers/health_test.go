package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthHandler_Health(t *testing.T) {
	logger := setupTestLogger()
	handler := NewHealthHandler(logger)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()

	handler.Health(w, req)

	resp := w.Result()
	defer func() {
		err := resp.Body.Close()
		assert.NoError(t, err)
	}()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var healthResp HealthResponse
	err := json.NewDecoder(resp.Body).Decode(&healthResp)
	assert.NoError(t, err)

	assert.Equal(t, "ok", healthResp.Status)
	assert.NotEmpty(t, healthResp.Version) // В данном коде "dev"
}
