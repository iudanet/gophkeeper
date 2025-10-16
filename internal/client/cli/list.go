package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
)

func RunList(ctx context.Context, args []string, boltStorage *boltdb.Storage) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. Usage: gophkeeper list <credentials|text|binary|card>")
	}

	dataType := args[0]

	switch dataType {
	case "credentials", "credential":
		return RunListCredentials(ctx, boltStorage)
	case "text":
		return fmt.Errorf("'list text' not implemented yet")
	case "binary":
		return fmt.Errorf("'list binary' not implemented yet")
	case "card", "cards":
		return fmt.Errorf("'list cards' not implemented yet")
	default:
		return fmt.Errorf("unknown data type: %s. Use: credentials, text, binary, or card", dataType)
	}
}

func RunListCredentials(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Saved Credentials ===")
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

	// Получаем список credentials
	credentials, err := dataService.ListCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if len(credentials) == 0 {
		fmt.Println("No credentials found.")
		fmt.Println()
		fmt.Println("Use 'gophkeeper add credential' to add your first credential.")
		return nil
	}

	fmt.Printf("Found %d credential(s):\n", len(credentials))
	fmt.Println()

	for i, cred := range credentials {
		fmt.Printf("%d. %s\n", i+1, cred.Name)
		fmt.Printf("   ID:    %s\n", cred.ID)
		fmt.Printf("   Login: %s\n", cred.Login)
		if cred.URL != "" {
			fmt.Printf("   URL:   %s\n", cred.URL)
		}
		if cred.Notes != "" {
			fmt.Printf("   Notes: %s\n", cred.Notes)
		}
		fmt.Println()
	}

	fmt.Println("Note: Passwords are hidden for security. Use 'gophkeeper get <id>' to view full details.")

	return nil
}
