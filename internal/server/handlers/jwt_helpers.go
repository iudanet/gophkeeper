package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims представляет JWT claims для нашего приложения
type CustomClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTConfig содержит конфигурацию для JWT
type JWTConfig struct {
	Secret          []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// GenerateAccessToken создает новый JWT access token
func GenerateAccessToken(cfg JWTConfig, userID, username string) (string, int64, error) {
	now := time.Now()
	expiresAt := now.Add(cfg.AccessTokenTTL)

	claims := CustomClaims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "gophkeeper",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(cfg.Secret)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, int64(cfg.AccessTokenTTL.Seconds()), nil
}

// ValidateAccessToken валидирует и парсит JWT access token
func ValidateAccessToken(cfg JWTConfig, tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем что используется правильный алгоритм подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return cfg.Secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// GenerateRefreshToken создает новый random refresh token
func GenerateRefreshToken(cfg JWTConfig) (string, time.Time, error) {
	// Генерируем случайные 32 байта
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to generate random token: %w", err)
	}

	// Кодируем в base64
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(cfg.RefreshTokenTTL)

	return token, expiresAt, nil
}
