package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/auth"
)

func (c *Cli) runLogout(ctx context.Context) error {
	fmt.Println("=== Logout ===")

	// Создаем auth.Service с authStore
	authService := auth.NewService(c.apiClient, c.authService)

	// Выполняем logout
	if err := authService.Logout(ctx, ); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	fmt.Println("✓ Logout successful!")
	fmt.Println("Your local session has been deleted.")

	return nil
}
