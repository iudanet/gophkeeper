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
	cred, err := c.dataService.GetCredential(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.displayCredential(cred)
	}

	// Пробуем получить как text
	text, err := c.dataService.GetTextData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.displayTextData(text)
	}

	// Пробуем получить как binary
	binary, err := c.dataService.GetBinaryData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.displayBinaryData(binary)
	}

	// Пробуем получить как card
	card, err := c.dataService.GetCardData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.displayCardData(card)
	}

	return fmt.Errorf("entry not found with ID: %s", entryID)
}

func (c *Cli) displayCredential(credential *models.Credential) error {
	fmt.Println("=== Credential Details ===")
	fmt.Println()

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

func (c *Cli) displayTextData(textData *models.TextData) error {
	fmt.Println("=== Text Data Details ===")
	fmt.Println()

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

func (c *Cli) displayBinaryData(binaryData *models.BinaryData) error {
	fmt.Println("=== Binary Data Details ===")
	fmt.Println()

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

func (c *Cli) displayCardData(card *models.CardData) error {
	fmt.Println("=== Card Data Details ===")
	fmt.Println()

	fmt.Printf("Name:   %s\n", card.Name)
	fmt.Printf("ID:     %s\n", card.ID)
	fmt.Printf("Number: %s\n", card.Number)
	if card.Holder != "" {
		fmt.Printf("Holder: %s\n", card.Holder)
	}
	if card.Expiry != "" {
		fmt.Printf("Expiry: %s\n", card.Expiry)
	}
	if card.CVV != "" {
		fmt.Printf("CVV:    %s\n", card.CVV)
	}
	if card.PIN != "" {
		fmt.Printf("PIN:    %s\n", card.PIN)
	}
	fmt.Println()

	return nil
}
