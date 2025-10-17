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

	// Проверяем срок действия токена и обновляем если нужно
	// Добавляем буфер 60 секунд - обновляем токен заранее
	expiresAt := time.Unix(c.authData.ExpiresAt, 0)
	now := time.Now()
	bufferTime := 60 * time.Second

	// Если токен истёк или скоро истечёт - обновляем через refresh token
	if now.Add(bufferTime).After(expiresAt) {
		fmt.Println()
		fmt.Println("Access token expired or expiring soon, refreshing...")

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

		fmt.Println("✓ Access token refreshed successfully")
	}

	accessToken := c.authData.AccessToken

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
