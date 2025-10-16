package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

func RunAdd(ctx context.Context, args []string, boltStorage *boltdb.Storage) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. Usage: gophkeeper add <credential|text|binary|card>")
	}

	dataType := args[0]

	switch dataType {
	case "credential":
		return RunAddCredential(ctx, boltStorage)
	case "text":
		return RunAddText(ctx, boltStorage)
	case "binary":
		return fmt.Errorf("'add binary' not fully implemented yet. Use: gophkeeper add text for now")
	case "card":
		return RunAddCard(ctx, boltStorage)
	default:
		return fmt.Errorf("unknown data type: %s. Use: credential, text, binary, or card", dataType)
	}
}

func RunAddCredential(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Add Credential ===")
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

	fmt.Println()
	fmt.Println("Enter credential details:")
	fmt.Println()

	// Запрашиваем данные credentials
	name, err := readInput("Name (e.g., 'GitHub', 'Gmail'): ")
	if err != nil {
		return fmt.Errorf("failed to read name: %w", err)
	}
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	login, err := readInput("Login/Email: ")
	if err != nil {
		return fmt.Errorf("failed to read login: %w", err)
	}
	if login == "" {
		return fmt.Errorf("login cannot be empty")
	}

	password, err := readPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	url, err := readInput("URL (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read URL: %w", err)
	}

	notes, err := readInput("Notes (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read notes: %w", err)
	}

	// Создаем credential
	cred := &models.Credential{
		Name:     name,
		Login:    login,
		Password: password,
		URL:      url,
		Notes:    notes,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
		},
	}

	// Получаем User ID из authData
	// Примечание: в текущей реализации userID хранится в authData (возможно потребуется добавить)
	// Для простоты используем username как userID
	userID := authData.Username

	// Генерируем nodeID (уникальный ID клиента)
	// В реальном приложении это должен быть постоянный ID, сохраненный в БД
	nodeID := fmt.Sprintf("%s-client", authData.Username)

	// Создаем data service
	dataService := data.NewService(boltStorage, keys.EncryptionKey, nodeID)

	// Добавляем credential
	if err := dataService.AddCredential(ctx, userID, cred); err != nil {
		return fmt.Errorf("failed to add credential: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Credential added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Login: %s\n", login)
	fmt.Println()
	fmt.Println("Note: Credential is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}

func RunAddText(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Add Text Data ===")
	fmt.Println()

	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	fmt.Println()
	fmt.Println("Enter text data details:")
	fmt.Println()

	name, err := readInput("Name (e.g., 'Secret Note'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	content, err := readInput("Content: ")
	if err != nil || content == "" {
		return fmt.Errorf("content cannot be empty")
	}

	textData := &models.TextData{
		Name:    name,
		Content: content,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
		},
	}

	userID := authData.Username
	nodeID := fmt.Sprintf("%s-client", authData.Username)
	dataService := data.NewService(boltStorage, keys.EncryptionKey, nodeID)

	if err := dataService.AddTextData(ctx, userID, textData); err != nil {
		return fmt.Errorf("failed to add text data: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Text data added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Println()
	fmt.Println("Note: Data is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}

func RunAddCard(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Add Card Data ===")
	fmt.Println()

	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	fmt.Println()
	fmt.Println("Enter card details:")
	fmt.Println()

	name, err := readInput("Card Name (e.g., 'Visa Gold'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	number, err := readInput("Card Number: ")
	if err != nil || number == "" {
		return fmt.Errorf("card number cannot be empty")
	}

	holder, err := readInput("Card Holder: ")
	if err != nil {
		return fmt.Errorf("failed to read holder: %w", err)
	}

	expiry, err := readInput("Expiry (MM/YY): ")
	if err != nil {
		return fmt.Errorf("failed to read expiry: %w", err)
	}

	cvv, err := readPassword("CVV: ")
	if err != nil {
		return fmt.Errorf("failed to read CVV: %w", err)
	}

	pin, err := readPassword("PIN (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read PIN: %w", err)
	}

	cardData := &models.CardData{
		Name:   name,
		Number: number,
		Holder: holder,
		Expiry: expiry,
		CVV:    cvv,
		PIN:    pin,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
		},
	}

	userID := authData.Username
	nodeID := fmt.Sprintf("%s-client", authData.Username)
	dataService := data.NewService(boltStorage, keys.EncryptionKey, nodeID)

	if err := dataService.AddCardData(ctx, userID, cardData); err != nil {
		return fmt.Errorf("failed to add card: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Card added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Println()
	fmt.Println("Note: Card is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}
