package cli

import (
	"context"
	"fmt"
	"time"
)

func (c *Cli) runSync(ctx context.Context) error {
	c.io.Println("=== Synchronization ===")

	// Используем уже расшифрованный access token из c.authData
	// (он был расшифрован в ReadMasterPassword)
	if c.authData == nil {
		return fmt.Errorf("not authenticated or encryption key not available")
	}

	// Проверяем срок действия токена и обновляем если нужно
	// Добавляем буфер 60 секунд - обновляем токен заранее
	expiresAt := time.Unix(c.authData.ExpiresAt, 0)
	now := time.Now()
	bufferTime := 60 * time.Second

	// Если токен истёк или скоро истечёт - обновляем через refresh token
	if now.Add(bufferTime).After(expiresAt) {
		c.io.Println()
		c.io.Println("Access token expired or expiring soon, refreshing...")

		// Вызываем authService.RefreshToken()
		if err := c.authService.RefreshToken(ctx); err != nil {
			return fmt.Errorf("failed to refresh access token: %w. Please login again", err)
		}

		// Получаем обновлённые токены из хранилища
		updatedAuthData, err := c.authService.GetAuthDecryptData(ctx)
		if err != nil {
			return fmt.Errorf("failed to get updated auth data: %w", err)
		}

		// Обновляем c.authData для использования в sync
		c.authData = updatedAuthData

		c.io.Println("✓ Access token refreshed successfully")
	}

	accessToken := c.authData.AccessToken

	c.io.Println()
	c.io.Println("Starting synchronization with server...")

	// Получаем userID
	userID := c.authData.UserID

	// Выполняем синхронизацию через готовый сервис
	result, err := c.syncService.Sync(ctx, userID, accessToken)
	if err != nil {
		return fmt.Errorf("synchronization failed: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Synchronization completed successfully!")
	c.io.Println()
	c.io.Printf("Pushed to server:   %d entries\n", result.PushedEntries)
	c.io.Printf("Pulled from server: %d entries\n", result.PulledEntries)
	c.io.Printf("Merged locally:     %d entries\n", result.MergedEntries)
	if result.Conflicts > 0 {
		c.io.Printf("Conflicts resolved: %d\n", result.Conflicts)
	}
	if result.SkippedEntries > 0 {
		c.io.Printf("Skipped (errors):   %d\n", result.SkippedEntries)
	}

	c.io.Println()
	c.io.Println("Your data is now synchronized with the server.")

	return nil
}
