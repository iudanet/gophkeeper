package cli

import (
	"context"
	"fmt"
)

func (c *Cli) runLogout(ctx context.Context) error {
	fmt.Println("=== Logout ===")

	// Выполняем logout через authService
	if err := c.authService.Logout(ctx); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	fmt.Println("✓ Logout successful!")
	fmt.Println("Your local session has been deleted.")

	return nil
}
