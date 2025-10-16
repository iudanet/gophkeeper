package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/client/sync"
	"github.com/iudanet/gophkeeper/internal/crypto"
)

func RunSync(ctx context.Context, apiClient *api.Client, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Synchronization ===")
	fmt.Println()

	// Проверяем авторизацию
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Запрашиваем master password для получения encryption_key
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Деривируем ключи
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// Получаем access token (расшифровываем)
	authStore := auth.NewAuthService(boltStorage, keys.EncryptionKey)
	authDataDecrypted, err := authStore.GetAuth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth data: %w", err)
	}
	accessToken := authDataDecrypted.AccessToken

	// Проверяем что токен не истек
	expiresAt := time.Unix(authData.ExpiresAt, 0)
	if time.Now().After(expiresAt) {
		return fmt.Errorf("access token has expired. Please login again")
	}

	fmt.Println()
	fmt.Println("Starting synchronization with server...")

	// Создаем logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Создаем sync service (передаем boltStorage как metadata storage тоже)
	syncService := sync.NewService(apiClient, boltStorage, boltStorage, logger)

	// Получаем userID (используем username как userID)
	userID := authData.Username

	// Выполняем синхронизацию
	result, err := syncService.Sync(ctx, userID, accessToken)
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
