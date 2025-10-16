package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/iudanet/gophkeeper/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient проверяет создание нового клиента
func TestNewClient(t *testing.T) {
	baseURL := "http://localhost:8080"
	client := NewClient(baseURL)

	assert.NotNil(t, client)
	assert.Equal(t, baseURL, client.baseURL)
	assert.NotNil(t, client.httpClient)
	assert.Equal(t, 30*time.Second, client.httpClient.Timeout)
}

// TestClient_Register проверяет успешную регистрацию
func TestClient_Register(t *testing.T) {
	// Создаем mock сервер
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Проверяем метод и путь
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/auth/register", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Декодируем запрос
		var req api.RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		// Проверяем поля запроса
		assert.Equal(t, "testuser", req.Username)
		assert.NotEmpty(t, req.AuthKeyHash)
		assert.NotEmpty(t, req.PublicSalt)

		// Возвращаем успешный ответ
		w.WriteHeader(http.StatusCreated)
		resp := api.RegisterResponse{
			UserID:  "user-123",
			Message: "Registration successful",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Создаем клиент
	client := NewClient(server.URL)

	// Выполняем запрос
	ctx := context.Background()
	req := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	resp, err := client.Register(ctx, req)

	// Проверяем результат
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "user-123", resp.UserID)
	assert.Equal(t, "Registration successful", resp.Message)
}

// TestClient_Register_Error проверяет обработку ошибок при регистрации
func TestClient_Register_Error(t *testing.T) {
	tests := []struct {
		responseBody   interface{}
		name           string
		expectedErrMsg string
		statusCode     int
	}{
		{
			name:       "User already exists",
			statusCode: http.StatusConflict,
			responseBody: api.ErrorResponse{
				Message: "user already exists",
			},
			expectedErrMsg: "server error (409): user already exists",
		},
		{
			name:       "Invalid request",
			statusCode: http.StatusBadRequest,
			responseBody: api.ErrorResponse{
				Message: "invalid username",
			},
			expectedErrMsg: "server error (400): invalid username",
		},
		{
			name:           "Internal server error",
			statusCode:     http.StatusInternalServerError,
			responseBody:   "Internal Server Error",
			expectedErrMsg: "request failed with status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				if errResp, ok := tt.responseBody.(api.ErrorResponse); ok {
					_ = json.NewEncoder(w).Encode(errResp)
				} else {
					_, _ = w.Write([]byte(tt.responseBody.(string)))
				}
			}))
			defer server.Close()

			client := NewClient(server.URL)
			ctx := context.Background()
			req := api.RegisterRequest{
				Username:    "testuser",
				AuthKeyHash: "hash123",
				PublicSalt:  "salt123",
			}

			resp, err := client.Register(ctx, req)

			require.Error(t, err)
			assert.Nil(t, resp)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}

// TestClient_GetSalt проверяет успешное получение соли
func TestClient_GetSalt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/api/v1/auth/salt/testuser", r.URL.Path)

		w.WriteHeader(http.StatusOK)
		resp := api.SaltResponse{
			PublicSalt: "base64encodedSalt",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.GetSalt(ctx, "testuser")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "base64encodedSalt", resp.PublicSalt)
}

// TestClient_GetSalt_NotFound проверяет обработку ошибки "пользователь не найден"
func TestClient_GetSalt_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		resp := api.ErrorResponse{
			Message: "user not found",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.GetSalt(ctx, "nonexistent")

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "server error (404): user not found")
}

// TestClient_Login проверяет успешный логин
func TestClient_Login(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/auth/login", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req api.LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "testuser", req.Username)
		assert.NotEmpty(t, req.AuthKeyHash)

		w.WriteHeader(http.StatusOK)
		resp := api.TokenResponse{
			UserID:       "user-uuid-123",
			AccessToken:  "access_token_123",
			RefreshToken: "refresh_token_456",
			ExpiresIn:    3600,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
	}

	resp, err := client.Login(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "user-uuid-123", resp.UserID)
	assert.Equal(t, "access_token_123", resp.AccessToken)
	assert.Equal(t, "refresh_token_456", resp.RefreshToken)
	assert.Equal(t, int64(3600), resp.ExpiresIn)
}

// TestClient_Login_UserIDRequired проверяет что UserID возвращается сервером
// Это критично для правильной работы синхронизации CRDT
func TestClient_Login_UserIDRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		resp := api.TokenResponse{
			UserID:       "2afeb7d9-7aea-47af-a96e-bbfbf3b3a5bf", // UUID формат
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			ExpiresIn:    900,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "hash",
	}

	resp, err := client.Login(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	// Критично: UserID должен быть UUID, не username
	assert.NotEmpty(t, resp.UserID)
	assert.Equal(t, "2afeb7d9-7aea-47af-a96e-bbfbf3b3a5bf", resp.UserID)
	// Проверяем что это UUID формат (содержит дефисы)
	assert.Contains(t, resp.UserID, "-")
}

// TestClient_Login_InvalidCredentials проверяет обработку неверных учетных данных
func TestClient_Login_InvalidCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := api.ErrorResponse{
			Message: "invalid credentials",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.LoginRequest{
		Username:    "testuser",
		AuthKeyHash: "wrong_hash",
	}

	resp, err := client.Login(ctx, req)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "server error (401): invalid credentials")
}

// TestClient_Logout проверяет успешный выход
func TestClient_Logout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/auth/logout", r.URL.Path)
		assert.Equal(t, "Bearer test_token", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		resp := map[string]string{"message": "Logout successful"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.Logout(ctx, "test_token")

	require.NoError(t, err)
}

// TestClient_Logout_Unauthorized проверяет обработку неавторизованного выхода
func TestClient_Logout_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := api.ErrorResponse{
			Message: "invalid token",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	err := client.Logout(ctx, "invalid_token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "server error (401): invalid token")
}

// TestClient_Sync проверяет успешную синхронизацию
func TestClient_Sync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/sync", r.URL.Path)
		assert.Equal(t, "Bearer test_token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var req api.SyncRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.NotEmpty(t, req.Entries)
		assert.Equal(t, 2, len(req.Entries))

		w.WriteHeader(http.StatusOK)
		resp := api.SyncResponse{
			Entries: []api.CRDTEntry{
				{
					ID:        "entry-1",
					UserID:    "user-123",
					DataType:  string(models.DataTypeCredential),
					Data:      []byte("encrypted_data"),
					Metadata:  "",
					Timestamp: time.Now().Unix(),
					Deleted:   false,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
			},
			CurrentTimestamp: time.Now().Unix(),
			Conflicts:        0,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	now := time.Now()
	req := api.SyncRequest{
		Entries: []api.CRDTEntry{
			{
				ID:        "entry-1",
				UserID:    "user-123",
				DataType:  string(models.DataTypeCredential),
				Data:      []byte("local_data"),
				Metadata:  "",
				Timestamp: now.Unix() - 100,
				Deleted:   false,
				CreatedAt: now.Add(-100 * time.Second),
				UpdatedAt: now.Add(-100 * time.Second),
			},
			{
				ID:        "entry-2",
				UserID:    "user-123",
				DataType:  string(models.DataTypeText),
				Data:      []byte("text_data"),
				Metadata:  "",
				Timestamp: now.Unix() - 50,
				Deleted:   false,
				CreatedAt: now.Add(-50 * time.Second),
				UpdatedAt: now.Add(-50 * time.Second),
			},
		},
		Since: 0,
	}

	resp, err := client.Sync(ctx, "test_token", req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Entries)
	assert.Equal(t, "entry-1", resp.Entries[0].ID)
	assert.Equal(t, string(models.DataTypeCredential), resp.Entries[0].DataType)
}

// TestClient_Sync_Unauthorized проверяет обработку неавторизованной синхронизации
func TestClient_Sync_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := api.ErrorResponse{
			Message: "token expired",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.SyncRequest{
		Entries: []api.CRDTEntry{},
		Since:   0,
	}

	resp, err := client.Sync(ctx, "expired_token", req)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "server error (401): token expired")
}

// TestClient_ContextCancellation проверяет отмену запроса через контекст
func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Имитируем долгий запрос
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL)

	// Создаем контекст с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	resp, err := client.Register(ctx, req)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

// TestClient_InvalidJSON проверяет обработку невалидного JSON в ответе
func TestClient_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json {{{"))
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	resp, err := client.Register(ctx, req)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "failed to decode response")
}

// TestClient_HTTPClientRedirect проверяет обработку редиректов
func TestClient_HTTPClientRedirect(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectCount < 3 {
			redirectCount++
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(http.StatusFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		resp := api.RegisterResponse{
			UserID:  "user-123",
			Message: "Success after redirect",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()
	req := api.RegisterRequest{
		Username:    "testuser",
		AuthKeyHash: "hash123",
		PublicSalt:  "salt123",
	}

	resp, err := client.Register(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "user-123", resp.UserID)
	assert.Equal(t, 3, redirectCount) // Проверяем что было 3 редиректа
}
