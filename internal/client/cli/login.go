package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/storage"
)

func (c *Cli) runLogin(ctx context.Context) error {
	fmt.Println("=== Login ===")
	fmt.Println()

	// Запрашиваем username
	username, err := readInput("Username: ")
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Запрашиваем master password
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println()
	fmt.Println("Authenticating...")

	// Создаем auth.Service (без authStore на этом этапе)
	authService := auth.NewService(c.apiClient, nil)

	// Логин
	result, err := authService.Login(ctx, username, masterPassword)
	if err != nil {
		return err
	}

	// Теперь у нас есть encryption_key, создаем AuthService (слой шифрования)
	authStore := auth.NewAuthService(c.boltStorage, result.EncryptionKey)

	// Сохраняем токены через слой шифрования
	authData := &storage.AuthData{
		Username:     result.Username,
		AccessToken:  result.AccessToken,  // plaintext
		RefreshToken: result.RefreshToken, // plaintext
		PublicSalt:   result.PublicSalt,
		ExpiresAt:    time.Now().Unix() + result.ExpiresIn,
	}

	if err := authStore.SaveAuth(ctx, authData); err != nil {
		return fmt.Errorf("failed to save auth data: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Login successful!")
	fmt.Printf("Username: %s\n", result.Username)
	fmt.Printf("Access token expires in: %d seconds\n", result.ExpiresIn)
	fmt.Println()
	fmt.Println("Your session has been saved securely.")

	return nil
}
