package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/storage"
)

func (c *Cli) runGet(ctx context.Context, args []string) error {
	// Проверяем наличие ID
	if len(args) == 0 {
		return fmt.Errorf("missing credential ID. Usage: gophkeeper get <id>")
	}

	credentialID := args[0]

	fmt.Println("=== Credential Details ===")

	// Получаем credential через data service
	cred, err := c.dataService.GetCredential(ctx, credentialID)
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
