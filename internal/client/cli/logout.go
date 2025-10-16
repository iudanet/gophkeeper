package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
)

func RunLogout(ctx context.Context, apiClient *api.Client, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Logout ===")
	fmt.Println()

	// Проверяем, есть ли сохраненная сессия
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			fmt.Println("No active session found.")
			return nil
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Нужен encryption_key для расшифровки токена
	// Запрашиваем master password
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Деривируем ключи
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// Создаем authStore с encryption_key
	authStore := auth.NewAuthService(boltStorage, keys.EncryptionKey)

	// Создаем auth.Service с authStore
	authService := auth.NewService(apiClient, authStore)

	// Выполняем logout
	if err := authService.Logout(ctx); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	fmt.Println("✓ Logout successful!")
	fmt.Println("Your local session has been deleted.")

	return nil
}
