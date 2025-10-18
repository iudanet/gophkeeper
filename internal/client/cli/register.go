package cli

import (
	"context"
	"fmt"
)

func (c *Cli) runRegister(ctx context.Context) error {
	fmt.Println("=== Registration ===")
	fmt.Println()

	// Запрашиваем username
	username, err := c.io.ReadInput("Username: ")
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Запрашиваем master password
	masterPassword, err := c.io.ReadPassword("Master password (min 12 chars): ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Подтверждение пароля
	confirmPassword, err := c.io.ReadPassword("Confirm master password: ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if masterPassword != confirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	fmt.Println()
	fmt.Println("Registering user...")

	// Регистрация через authService
	result, err := c.authService.Register(ctx, username, masterPassword)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ Registration successful!")
	fmt.Printf("User ID: %s\n", result.UserID)
	fmt.Printf("Username: %s\n", result.Username)
	fmt.Printf("Device ID: %s\n", result.NodeID)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Remember your master password!")
	fmt.Println("   If you lose it, you will NOT be able to recover your data.")
	fmt.Println()
	fmt.Println("Please run 'gophkeeper login' to start using the service.")

	return nil
}
