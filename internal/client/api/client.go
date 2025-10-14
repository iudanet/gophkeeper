package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/iudanet/gophkeeper/pkg/api"
)

// Client представляет HTTP клиент для взаимодействия с сервером
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient создает новый API клиент
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Настройка обработки редиректов
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Ограничиваем количество редиректов
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				// Копируем заголовки Authorization при редиректе
				if len(via) > 0 && via[0].Header.Get("Authorization") != "" {
					req.Header.Set("Authorization", via[0].Header.Get("Authorization"))
				}
				return nil
			},
		},
	}
}

// Register регистрирует нового пользователя
func (c *Client) Register(ctx context.Context, req api.RegisterRequest) (*api.RegisterResponse, error) {
	var resp api.RegisterResponse
	err := c.doRequest(ctx, "POST", "/api/v1/auth/register", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("register request failed: %w", err)
	}
	return &resp, nil
}

// GetSalt получает public_salt пользователя
func (c *Client) GetSalt(ctx context.Context, username string) (*api.GetSaltResponse, error) {
	var resp api.GetSaltResponse
	url := fmt.Sprintf("/api/v1/auth/salt/%s", username)
	err := c.doRequest(ctx, "GET", url, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("get salt request failed: %w", err)
	}
	return &resp, nil
}

// Login выполняет аутентификацию пользователя
func (c *Client) Login(ctx context.Context, req api.LoginRequest) (*api.TokenResponse, error) {
	var resp api.TokenResponse
	err := c.doRequest(ctx, "POST", "/api/v1/auth/login", req, &resp)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	return &resp, nil
}

// doRequest выполняет HTTP запрос
func (c *Client) doRequest(ctx context.Context, method, path string, body, result interface{}) error {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Читаем тело ответа
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Проверяем статус код
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp api.ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return fmt.Errorf("server error (%d): %s", resp.StatusCode, errResp.Message)
		}
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Декодируем успешный ответ
	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
