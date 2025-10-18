package cli

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/iudanet/gophkeeper/internal/models"
)

var usage = "Usage: gophkeeper add <credential|text|binary|card> [--sync]"

func (c *Cli) runAdd(ctx context.Context, args []string) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. %s", usage)
	}

	// Парсим флаг --sync
	syncFlag := false
	dataType := args[0]

	// Проверяем наличие флага --sync в аргументах
	if len(args) > 1 {
		for _, arg := range args[1:] {
			if arg == "--sync" {
				syncFlag = true
				break
			}
		}
	}

	switch dataType {
	case "credential":
		return c.runAddCredential(ctx, syncFlag)
	case "text":
		return c.runAddText(ctx, syncFlag)
	case "binary":
		return c.runAddBinary(ctx, syncFlag)
	case "card":
		return c.runAddCard(ctx, syncFlag)
	default:
		return fmt.Errorf("unknown data type: %s. %s", dataType, usage)
	}
}

func (c *Cli) runAddCredential(ctx context.Context, autoSync bool) error {
	c.io.Println("=== Add Credential ===")
	c.io.Println()
	c.io.Println("Enter credential details:")
	c.io.Println()

	name, err := c.io.ReadInput("Name (e.g., 'GitHub', 'Gmail'): ")
	if err != nil {
		return fmt.Errorf("failed to read name: %w", err)
	}
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	login, err := c.io.ReadInput("Login/Email: ")
	if err != nil {
		return fmt.Errorf("failed to read login: %w", err)
	}
	if login == "" {
		return fmt.Errorf("login cannot be empty")
	}

	password, err := c.io.ReadPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	url, err := c.io.ReadInput("URL (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read URL: %w", err)
	}

	notes, err := c.io.ReadInput("Notes (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read notes: %w", err)
	}

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

	userID := c.authData.UserID

	if err := c.dataService.AddCredential(ctx, userID, c.authData.NodeID, c.encryptionKey, cred); err != nil {
		return fmt.Errorf("failed to add credential: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Credential added successfully!")
	c.io.Printf("Name: %s\n", name)
	c.io.Printf("Login: %s\n", login)
	c.io.Println()

	if autoSync {
		c.io.Println("Syncing with server...")
		if err := c.runSync(ctx); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}
	} else {
		c.io.Println("Note: Credential is stored locally. Run 'gophkeeper sync' to sync with server.")
	}
	return nil
}

func (c *Cli) runAddText(ctx context.Context, autoSync bool) error {
	c.io.Println("=== Add Text Data ===")
	c.io.Println()
	c.io.Println("Enter text data details:")
	c.io.Println()

	name, err := c.io.ReadInput("Name (e.g., 'Secret Note'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	content, err := c.io.ReadInput("Content: ")
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

	if err := c.dataService.AddTextData(ctx, userID, c.authData.NodeID, c.encryptionKey, textData); err != nil {
		return fmt.Errorf("failed to add text data: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Text data added successfully!")
	c.io.Printf("Name: %s\n", name)
	c.io.Println()

	// Автоматическая синхронизация если флаг установлен
	if autoSync {
		c.io.Println("Syncing with server...")
		if err := c.runSync(ctx); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}
	} else {
		c.io.Println("Note: Data is stored locally. Run 'gophkeeper sync' to sync with server.")
	}

	return nil
}

func (c *Cli) runAddCard(ctx context.Context, autoSync bool) error {
	c.io.Println("=== Add Card Data ===")
	c.io.Println()
	c.io.Println("Enter card details:")
	c.io.Println()

	name, err := c.io.ReadInput("Card Name (e.g., 'Visa Gold'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	number, err := c.io.ReadInput("Card Number: ")
	if err != nil || number == "" {
		return fmt.Errorf("card number cannot be empty")
	}

	holder, err := c.io.ReadInput("Card Holder: ")
	if err != nil {
		return fmt.Errorf("failed to read holder: %w", err)
	}

	expiry, err := c.io.ReadInput("Expiry (MM/YY): ")
	if err != nil {
		return fmt.Errorf("failed to read expiry: %w", err)
	}

	cvv, err := c.io.ReadPassword("CVV: ")
	if err != nil {
		return fmt.Errorf("failed to read CVV: %w", err)
	}

	pin, err := c.io.ReadPassword("PIN (optional): ")
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

	if err := c.dataService.AddCardData(ctx, userID, c.authData.NodeID, c.encryptionKey, cardData); err != nil {
		return fmt.Errorf("failed to add card: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Card added successfully!")
	c.io.Printf("Name: %s\n", name)
	c.io.Println()

	// Автоматическая синхронизация если флаг установлен
	if autoSync {
		c.io.Println("Syncing with server...")
		if err := c.runSync(ctx); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}
	} else {
		c.io.Println("Note: Card is stored locally. Run 'gophkeeper sync' to sync with server.")
	}

	return nil
}

func (c *Cli) runAddBinary(ctx context.Context, autoSync bool) error {
	c.io.Println("=== Add Binary Data ===")
	c.io.Println()
	c.io.Println("Enter binary file details:")
	c.io.Println()

	name, err := c.io.ReadInput("Name (e.g., 'Passport Scan'): ")
	if err != nil || name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	filePath, err := c.io.ReadInput("File path: ")
	if err != nil || filePath == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Читаем файл
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Получаем имя файла из пути
	filename := filepath.Base(filePath)

	// Определяем MIME type через пакет mime
	ext := strings.ToLower(filepath.Ext(filename))
	mimeType := mime.TypeByExtension(ext)

	if mimeType == "" {
		mimeType = http.DetectContentType(content)
	}

	binaryData := &models.BinaryData{
		Name:     name,
		MimeType: mimeType,
		Data:     content,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
			CustomFields: map[string]string{
				"filename": filename,
			},
		},
	}

	userID := c.authData.UserID

	if err := c.dataService.AddBinaryData(ctx, userID, c.authData.NodeID, c.encryptionKey, binaryData); err != nil {
		return fmt.Errorf("failed to add binary data: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ File added successfully!")
	c.io.Printf("Name:     %s\n", name)
	if filename, ok := binaryData.Metadata.CustomFields["filename"]; ok {
		c.io.Printf("Filename: %s\n", filename)
	}
	c.io.Printf("Size:     %d bytes\n", len(content))
	c.io.Println()

	// Автоматическая синхронизация если флаг установлен
	if autoSync {
		c.io.Println("Syncing with server...")
		if err := c.runSync(ctx); err != nil {
			return fmt.Errorf("failed to sync: %w", err)
		}
	} else {
		c.io.Println("Note: File is stored locally. Run 'gophkeeper sync' to sync with server.")
	}

	return nil
}
