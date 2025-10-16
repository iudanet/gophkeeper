package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
)

func (c *Cli) runDelete(ctx context.Context, args []string) error {
	// Проверяем наличие ID
	if len(args) == 0 {
		return fmt.Errorf("missing credential ID. Usage: gophkeeper delete <id>")
	}

	credentialID := args[0]

	fmt.Println("=== Delete Credential ===")

	// Генерируем nodeID
	nodeID := fmt.Sprintf("%s-client", c.authData.Username)

	// Создаем data service
	dataService := data.NewService(c.boltStorage, c.keys.EncryptionKey, nodeID)

	// Сначала получаем credential для показа информации
	cred, err := dataService.GetCredential(ctx, credentialID)
	if err != nil {
		if err == storage.ErrEntryNotFound {
			return fmt.Errorf("credential not found with ID: %s", credentialID)
		}
		return fmt.Errorf("failed to get credential: %w", err)
	}

	// Показываем информацию о credential который будет удален
	fmt.Println()
	fmt.Println("About to delete:")
	fmt.Printf("  Name:  %s\n", cred.Name)
	fmt.Printf("  Login: %s\n", cred.Login)
	if cred.URL != "" {
		fmt.Printf("  URL:   %s\n", cred.URL)
	}
	fmt.Println()

	// Запрашиваем подтверждение
	confirm, err := readInput("Are you sure you want to delete this credential? (yes/no): ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" && confirm != "y" {
		fmt.Println()
		fmt.Println("Deletion cancelled.")
		return nil
	}

	// Удаляем credential (soft delete)
	if err := dataService.DeleteCredential(ctx, credentialID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Credential deleted successfully!")
	fmt.Println()
	fmt.Println("Note: This is a soft delete. The credential is marked as deleted locally.")
	fmt.Println("      Run 'gophkeeper sync' to sync with server.")

	return nil
}
