package cli

import (
	"context"
	"fmt"
	"time"
)

func (c *Cli) runSync(ctx context.Context) error {
	fmt.Println("=== Synchronization ===")

	// Используем уже расшифрованный access token из c.authData
	// (он был расшифрован в ReadMasterPassword)
	if c.authData == nil {
		return fmt.Errorf("not authenticated or encryption key not available")
	}
	accessToken := c.authData.AccessToken

	// Проверяем что токен не истек
	expiresAt := time.Unix(c.authData.ExpiresAt, 0)
	if time.Now().After(expiresAt) {
		return fmt.Errorf("access token has expired. Please login again")
	}

	fmt.Println()
	fmt.Println("Starting synchronization with server...")

	// Получаем userID
	userID := c.authData.UserID

	// Выполняем синхронизацию через готовый сервис
	result, err := c.syncService.Sync(ctx, userID, accessToken)
	if err != nil {
		return fmt.Errorf("synchronization failed: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Synchronization completed successfully!")
	fmt.Println()
	fmt.Printf("Pushed to server:   %d entries\n", result.PushedEntries)
	fmt.Printf("Pulled from server: %d entries\n", result.PulledEntries)
	fmt.Printf("Merged locally:     %d entries\n", result.MergedEntries)
	if result.Conflicts > 0 {
		fmt.Printf("Conflicts resolved: %d\n", result.Conflicts)
	}
	if result.SkippedEntries > 0 {
		fmt.Printf("Skipped (errors):   %d\n", result.SkippedEntries)
	}

	fmt.Println()
	fmt.Println("Your data is now synchronized with the server.")

	return nil
}
