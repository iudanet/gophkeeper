package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Service provides JWT token generation and validation
type Service struct {
	secret          []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

// Claims represents JWT claims
type Claims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// NewService creates a new JWT service
// secret should be a cryptographically secure random string
func NewService(secret string, accessTokenTTL, refreshTokenTTL time.Duration) *Service {
	return &Service{
		secret:          []byte(secret),
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// GenerateAccessToken creates a new JWT access token
func (s *Service) GenerateAccessToken(userID, username string) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(s.accessTokenTTL)

	claims := Claims{
		UserID:    userID,
		Username:  username,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	token, err := s.createToken(claims)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create access token: %w", err)
	}

	return token, int64(s.accessTokenTTL.Seconds()), nil
}

// GenerateRefreshToken creates a new random refresh token
func (s *Service) GenerateRefreshToken() (string, time.Time, error) {
	// Генерируем случайные 32 байта
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate random token: %w", err)
	}

	// Кодируем в base64
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(s.refreshTokenTTL)

	return token, expiresAt, nil
}

// ValidateAccessToken validates and parses JWT access token
func (s *Service) ValidateAccessToken(token string) (*Claims, error) {
	// Разделяем токен на части
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Проверяем подпись
	signatureInput := parts[0] + "." + parts[1]
	expectedSignature := s.sign(signatureInput)
	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Декодируем payload
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	// Парсим claims
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Проверяем срок действия
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// createToken создает JWT токен из claims
func (s *Service) createToken(claims Claims) (string, error) {
	// Header (алгоритм HS256)
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	// Payload (claims)
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Кодируем в base64
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Создаем подпись
	signatureInput := headerB64 + "." + claimsB64
	signature := s.sign(signatureInput)

	// Собираем токен
	token := signatureInput + "." + signature

	return token, nil
}

// sign создает HMAC-SHA256 подпись
func (s *Service) sign(data string) string {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte(data))
	signature := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(signature)
}
