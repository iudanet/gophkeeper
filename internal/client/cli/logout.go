package cli

import (
	"context"
	"fmt"
)

func (c *Cli) runLogout(ctx context.Context) error {
	c.io.Println("=== Logout ===")

	// Выполняем logout через authService
	if err := c.authService.Logout(ctx); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	c.io.Println("✓ Logout successful!")
	c.io.Println("Your local session has been deleted.")

	return nil
}
