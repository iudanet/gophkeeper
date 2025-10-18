package cli

import (
	"context"
	"fmt"
	"time"
)

func (c *Cli) runStatus(ctx context.Context) error {
	c.io.Println("=== Authentication Status ===")
	c.io.Println()

	// Проверяем наличие сохраненной сессии
	isAuth, err := c.authService.IsAuthenticated(ctx)
	if err != nil {
		return fmt.Errorf("failed to check authentication: %w", err)
	}

	if !isAuth {
		c.io.Println("Status: Not authenticated")
		c.io.Println()
		c.io.Println("Run 'gophkeeper login' to authenticate.")
		return nil
	}

	// Получаем зашифрованные данные (для отображения username/expiry не нужна расшифровка токенов)
	authData, err := c.authService.GetAuthEncryptData(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	expiresAt := time.Unix(authData.ExpiresAt, 0)
	remaining := time.Until(expiresAt)

	c.io.Println("Status: Authenticated")
	fmt.Printf("Username: %s\n", authData.Username)
	fmt.Printf("Token expires: %s\n", expiresAt.Format(time.RFC3339))

	if remaining > 0 {
		fmt.Printf("Time remaining: %s\n", remaining.Round(time.Second))
	} else {
		c.io.Println("⚠️  Token has expired. Please login again.")
	}

	// Получаем количество записей, ожидающих синхронизации
	pendingCount, err := c.syncService.GetPendingSyncCount(ctx)
	if err != nil {
		// Не прерываем выполнение, просто логируем
		fmt.Printf("\nWarning: Failed to get pending sync count: %v\n", err)
	} else {
		c.io.Println()
		if pendingCount > 0 {
			fmt.Printf("⚠️  Pending sync: %d record(s) waiting to be synchronized\n", pendingCount)
			c.io.Println("Run 'gophkeeper sync' to synchronize with server.")
		} else {
			c.io.Println("✓ All data synchronized with server")
		}
	}

	return nil
}
