package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/iudanet/gophkeeper/internal/models"
)

func (c *Cli) runGet(ctx context.Context, args []string) error {
	// Проверяем наличие ID
	if len(args) == 0 {
		return fmt.Errorf("missing entry ID. Usage: gophkeeper get <id>")
	}

	entryID := args[0]

	// Пробуем получить как credential
	cred, err := c.dataService.GetCredential(ctx, entryID)
	if err == nil {
		return c.displayCredential(cred)
	}

	// Пробуем получить как text
	text, err := c.dataService.GetTextData(ctx, entryID)
	if err == nil {
		return c.displayTextData(text)
	}

	// Пробуем получить как binary
	binary, err := c.dataService.GetBinaryData(ctx, entryID)
	if err == nil {
		return c.displayBinaryData(binary)
	}

	// Пробуем получить как card
	card, err := c.dataService.GetCardData(ctx, entryID)
	if err == nil {
		return c.displayCardData(card)
	}

	return fmt.Errorf("entry not found with ID: %s", entryID)
}

func (c *Cli) displayCredential(cred interface{}) error {
	fmt.Println("=== Credential Details ===")
	fmt.Println()

	// Type assertion
	credential, ok := cred.(*models.Credential)
	if !ok {
		return fmt.Errorf("invalid credential data")
	}

	fmt.Printf("Name:     %s\n", credential.Name)
	fmt.Printf("ID:       %s\n", credential.ID)
	fmt.Printf("Login:    %s\n", credential.Login)
	fmt.Printf("Password: %s\n", credential.Password)
	if credential.URL != "" {
		fmt.Printf("URL:      %s\n", credential.URL)
	}
	if credential.Notes != "" {
		fmt.Printf("Notes:    %s\n", credential.Notes)
	}
	fmt.Println()

	return nil
}

func (c *Cli) displayTextData(text interface{}) error {
	fmt.Println("=== Text Data Details ===")
	fmt.Println()

	textData, ok := text.(*models.TextData)
	if !ok {
		return fmt.Errorf("invalid text data")
	}

	fmt.Printf("Name:    %s\n", textData.Name)
	fmt.Printf("ID:      %s\n", textData.ID)
	fmt.Println()
	fmt.Println("Content:")
	fmt.Println("---")
	fmt.Println(textData.Content)
	fmt.Println("---")
	fmt.Println()

	return nil
}

func (c *Cli) displayBinaryData(binary interface{}) error {
	fmt.Println("=== Binary Data Details ===")
	fmt.Println()

	binaryData, ok := binary.(*models.BinaryData)
	if !ok {
		return fmt.Errorf("invalid binary data")
	}

	fmt.Printf("Name:     %s\n", binaryData.Name)
	fmt.Printf("ID:       %s\n", binaryData.ID)
	if filename, ok := binaryData.Metadata.CustomFields["filename"]; ok {
		fmt.Printf("Filename: %s\n", filename)
	}
	fmt.Printf("Size:     %d bytes\n", len(binaryData.Data))
	if binaryData.MimeType != "" {
		fmt.Printf("Type:     %s\n", binaryData.MimeType)
	}
	fmt.Println()

	// Спрашиваем где сохранить файл
	savePath, err := readInput("Save to file (press Enter to skip): ")
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if savePath != "" {
		// Сохраняем файл
		if err := os.WriteFile(savePath, binaryData.Data, 0600); err != nil {
			return fmt.Errorf("failed to save file: %w", err)
		}
		fmt.Printf("✓ File saved to: %s\n", savePath)
	}
	fmt.Println()

	return nil
}

func (c *Cli) displayCardData(card interface{}) error {
	fmt.Println("=== Card Data Details ===")
	fmt.Println()

	cardData, ok := card.(*models.CardData)
	if !ok {
		return fmt.Errorf("invalid card data")
	}

	fmt.Printf("Name:   %s\n", cardData.Name)
	fmt.Printf("ID:     %s\n", cardData.ID)
	fmt.Printf("Number: %s\n", cardData.Number)
	if cardData.Holder != "" {
		fmt.Printf("Holder: %s\n", cardData.Holder)
	}
	if cardData.Expiry != "" {
		fmt.Printf("Expiry: %s\n", cardData.Expiry)
	}
	if cardData.CVV != "" {
		fmt.Printf("CVV:    %s\n", cardData.CVV)
	}
	if cardData.PIN != "" {
		fmt.Printf("PIN:    %s\n", cardData.PIN)
	}
	fmt.Println()

	return nil
}
