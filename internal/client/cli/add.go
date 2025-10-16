package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/iudanet/gophkeeper/internal/models"
)

func (c *Cli) runAdd(ctx context.Context, args []string) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. Usage: gophkeeper add <credential|text|binary|card>")
	}

	dataType := args[0]

	switch dataType {
	case "credential":
		return c.runAddCredential(ctx)
	case "text":
		return c.runAddText(ctx)
	case "binary":
		return c.runAddBinary(ctx)
	case "card":
		return c.runAddCard(ctx)
	default:
		return fmt.Errorf("unknown data type: %s. Use: credential, text, binary, or card", dataType)
	}
}

func (c *Cli) runAddCredential(ctx context.Context) error {
	fmt.Println("=== Add Credential ===")
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

	// Используем UserID из authData
	userID := c.authData.UserID

	// Добавляем credential через data service
	if err := c.dataService.AddCredential(ctx, userID, cred); err != nil {
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

func (c *Cli) runAddText(ctx context.Context) error {
	fmt.Println("=== Add Text Data ===")
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

	userID := c.authData.UserID

	if err := c.dataService.AddTextData(ctx, userID, textData); err != nil {
		return fmt.Errorf("failed to add text data: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Text data added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Println()
	fmt.Println("Note: Data is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}

func (c *Cli) runAddCard(ctx context.Context) error {
	fmt.Println("=== Add Card Data ===")
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

	userID := c.authData.UserID

	if err := c.dataService.AddCardData(ctx, userID, cardData); err != nil {
		return fmt.Errorf("failed to add card: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Card added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Println()
	fmt.Println("Note: Card is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}

func (c *Cli) runAddBinary(ctx context.Context) error {
	fmt.Println("=== Add Binary Data ===")
	fmt.Println()
	fmt.Println("Enter binary file details:")
	fmt.Println()

	name, err := readInput("Name (e.g., 'Passport Scan'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	filepath, err := readInput("File path: ")
	if err != nil || filepath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Читаем файл
	content, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Получаем имя файла
	filename := filepath
	if strings.Contains(filepath, "/") {
		parts := strings.Split(filepath, "/")
		filename = parts[len(parts)-1]
	} else if strings.Contains(filepath, "\\") {
		parts := strings.Split(filepath, "\\")
		filename = parts[len(parts)-1]
	}

	// Определяем MIME type (простая имплементация)
	mimeType := ""
	if strings.HasSuffix(filename, ".pdf") {
		mimeType = "application/pdf"
	} else if strings.HasSuffix(filename, ".jpg") || strings.HasSuffix(filename, ".jpeg") {
		mimeType = "image/jpeg"
	} else if strings.HasSuffix(filename, ".png") {
		mimeType = "image/png"
	} else if strings.HasSuffix(filename, ".txt") {
		mimeType = "text/plain"
	}

	binaryData := &models.BinaryData{
		Name:     name,
		MimeType: mimeType,
		Data:     content,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
			CustomFields: map[string]string{
				"filename": filename, // Сохраняем оригинальное имя файла в метаданных
			},
		},
	}

	userID := c.authData.UserID

	if err := c.dataService.AddBinaryData(ctx, userID, binaryData); err != nil {
		return fmt.Errorf("failed to add binary data: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ File added successfully!")
	fmt.Printf("Name:     %s\n", name)
	if filename, ok := binaryData.Metadata.CustomFields["filename"]; ok {
		fmt.Printf("Filename: %s\n", filename)
	}
	fmt.Printf("Size:     %d bytes\n", len(content))
	fmt.Println()
	fmt.Println("Note: File is stored locally. Run 'gophkeeper sync' to sync with server.")

	return nil
}
