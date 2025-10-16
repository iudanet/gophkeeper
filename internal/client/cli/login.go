package cli

import (
	"context"
	"fmt"
	"time"

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

	// Получаем master password из различных источников
	pass, err := c.getMasterPassword(*c.pass)
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}
	// очищаем пароли так как больше ненадо
	c.pass = nil
	fmt.Println()
	fmt.Println("Authenticating...")

	// Логин через authService
	result, err := c.authService.Login(ctx, username, pass)
	if err != nil {
		return err
	}

	// Устанавливаем ключ шифрования в authService
	c.authService.SetEncryptionKey(result.EncryptionKey)

	// Сохраняем токены через authService (теперь с установленным ключом)
	authData := &storage.AuthData{
		Username:     result.Username,
		UserID:       result.UserID,       // User UUID from server
		NodeID:       result.NodeID,       // уникальный ID клиента для CRDT
		AccessToken:  result.AccessToken,  // plaintext
		RefreshToken: result.RefreshToken, // plaintext
		PublicSalt:   result.PublicSalt,
		ExpiresAt:    time.Now().Unix() + result.ExpiresIn,
	}

	if err := c.authService.SaveAuth(ctx, authData); err != nil {
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
