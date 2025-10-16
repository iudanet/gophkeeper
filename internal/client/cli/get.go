package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
)

func RunGet(ctx context.Context, args []string, boltStorage *boltdb.Storage) error {
	// Проверяем наличие ID
	if len(args) == 0 {
		return fmt.Errorf("missing credential ID. Usage: gophkeeper get <id>")
	}

	credentialID := args[0]

	fmt.Println("=== Credential Details ===")
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

	// Генерируем nodeID
	nodeID := fmt.Sprintf("%s-client", authData.Username)

	// Создаем data service
	dataService := data.NewService(boltStorage, keys.EncryptionKey, nodeID)

	// Получаем credential
	cred, err := dataService.GetCredential(ctx, credentialID)
	if err != nil {
		if err == storage.ErrEntryNotFound {
			return fmt.Errorf("credential not found with ID: %s", credentialID)
		}
		return fmt.Errorf("failed to get credential: %w", err)
	}

	fmt.Println()
	fmt.Printf("Name:     %s\n", cred.Name)
	fmt.Printf("ID:       %s\n", cred.ID)
	fmt.Printf("Login:    %s\n", cred.Login)
	fmt.Printf("Password: %s\n", cred.Password)
	if cred.URL != "" {
		fmt.Printf("URL:      %s\n", cred.URL)
	}
	if cred.Notes != "" {
		fmt.Printf("Notes:    %s\n", cred.Notes)
	}
	fmt.Println()

	return nil
}
