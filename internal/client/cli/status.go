package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
)

func RunStatus(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Authentication Status ===")
	fmt.Println()

	// Проверяем наличие сохраненной сессии
	isAuth, err := boltStorage.IsAuthenticated(ctx)
	if err != nil {
		return fmt.Errorf("failed to check authentication: %w", err)
	}

	if !isAuth {
		fmt.Println("Status: Not authenticated")
		fmt.Println()
		fmt.Println("Run 'gophkeeper login' to authenticate.")
		return nil
	}

	// Получаем данные
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	expiresAt := time.Unix(authData.ExpiresAt, 0)
	remaining := time.Until(expiresAt)

	fmt.Println("Status: Authenticated")
	fmt.Printf("Username: %s\n", authData.Username)
	fmt.Printf("Token expires: %s\n", expiresAt.Format(time.RFC3339))

	if remaining > 0 {
		fmt.Printf("Time remaining: %s\n", remaining.Round(time.Second))
	} else {
		fmt.Println("⚠️  Token has expired. Please login again.")
	}

	return nil
}
