package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/iudanet/gophkeeper/pkg/api"
)

//go:generate moq -out apiclient_mock.go . ClientAPI

var _ ClientAPI = (*Client)(nil)

// ClientAPI определяет интерфейс методов HTTP клиента для взаимодействия с сервером
type ClientAPI interface {
	// Register регистрирует нового пользователя
	Register(ctx context.Context, req api.RegisterRequest) (*api.RegisterResponse, error)

	// GetSalt получает public salt пользователя по username
	GetSalt(ctx context.Context, username string) (*api.SaltResponse, error)

	// Login выполняет аутентификацию пользователя
	Login(ctx context.Context, req api.LoginRequest) (*api.TokenResponse, error)

	// Refresh обновляет access token используя refresh token
	Refresh(ctx context.Context, refreshToken string) (*api.TokenResponse, error)

	// Logout выполняет выход из системы
	Logout(ctx context.Context, accessToken string) error

	// Sync выполняет синхронизацию данных с сервером
	Sync(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error)
}

// Client представляет HTTP клиент для взаимодействия с сервером
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// ClientOptions опции для создания API клиента
type ClientOptions struct {
	BaseURL    string
	CACertPath string // Путь к CA сертификату для проверки самоподписанного сертификата сервера
	Insecure   bool   // Пропустить проверку TLS сертификата (только для разработки!)
}

// NewClient создает новый API клиент с настройками по умолчанию
func NewClient(baseURL string) ClientAPI {
	return NewClientWithOptions(ClientOptions{
		BaseURL:  baseURL,
		Insecure: false,
	})
}

// NewClientWithOptions создает новый API клиент с кастомными опциями TLS
func NewClientWithOptions(opts ClientOptions) *Client {
	// Создаем базовый HTTP transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Если включен insecure режим - отключаем валидацию сертификатов
	if opts.Insecure {
		transport.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 - опция для dev окружения
	}

	// Если указан CA сертификат - загружаем его для валидации самоподписанных сертификатов
	if opts.CACertPath != "" && !opts.Insecure {
		caCert, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			// Логируем ошибку, но не падаем - будем использовать системные CA
			fmt.Fprintf(os.Stderr, "Warning: failed to load CA certificate from %s: %v\n", opts.CACertPath, err)
			fmt.Fprintf(os.Stderr, "Falling back to system CA certificates\n")
		} else {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				fmt.Fprintf(os.Stderr, "Warning: failed to parse CA certificate from %s\n", opts.CACertPath)
				fmt.Fprintf(os.Stderr, "Falling back to system CA certificates\n")
			} else {
				// Успешно загрузили CA сертификат
				transport.TLSClientConfig.RootCAs = caCertPool
			}
		}
	}
	// Если CA не указан и не insecure - будет использоваться системный CA pool (по умолчанию)

	return &Client{
		baseURL: opts.BaseURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
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
func (c *Client) GetSalt(ctx context.Context, username string) (*api.SaltResponse, error) {
	var resp api.SaltResponse
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

// Refresh обновляет access token используя refresh token
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*api.TokenResponse, error) {
	var resp api.TokenResponse
	err := c.doAuthRequest(ctx, "POST", "/api/v1/auth/refresh", refreshToken, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	return &resp, nil
}

// Logout выполняет выход из системы
func (c *Client) Logout(ctx context.Context, accessToken string) error {
	return c.doAuthRequest(ctx, "POST", "/api/v1/auth/logout", accessToken, nil, nil)
}

// Sync выполняет синхронизацию данных с сервером
func (c *Client) Sync(ctx context.Context, accessToken string, req api.SyncRequest) (*api.SyncResponse, error) {
	var resp api.SyncResponse
	err := c.doAuthRequest(ctx, "POST", "/api/v1/sync", accessToken, req, &resp)
	if err != nil {
		return nil, fmt.Errorf("sync request failed: %w", err)
	}
	return &resp, nil
}

// doAuthRequest выполняет HTTP запрос с авторизацией
func (c *Client) doAuthRequest(ctx context.Context, method, path, token string, body, result interface{}) error {
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

	// Добавляем Authorization header
	req.Header.Set("Authorization", "Bearer "+token)

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
