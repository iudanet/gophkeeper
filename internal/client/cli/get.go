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
	c.io.Println("=== Credential Details ===")
	c.io.Println()

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
	c.io.Println()

	return nil
}

func (c *Cli) displayTextData(textData *models.TextData) error {
	c.io.Println("=== Text Data Details ===")
	c.io.Println()

	fmt.Printf("Name:    %s\n", textData.Name)
	fmt.Printf("ID:      %s\n", textData.ID)
	c.io.Println()
	c.io.Println("Content:")
	c.io.Println("---")
	c.io.Println(textData.Content)
	c.io.Println("---")
	c.io.Println()

	return nil
}

func (c *Cli) displayBinaryData(binaryData *models.BinaryData) error {
	c.io.Println("=== Binary Data Details ===")
	c.io.Println()

	fmt.Printf("Name:     %s\n", binaryData.Name)
	fmt.Printf("ID:       %s\n", binaryData.ID)
	if filename, ok := binaryData.Metadata.CustomFields["filename"]; ok {
		fmt.Printf("Filename: %s\n", filename)
	}
	fmt.Printf("Size:     %d bytes\n", len(binaryData.Data))
	if binaryData.MimeType != "" {
		fmt.Printf("Type:     %s\n", binaryData.MimeType)
	}
	c.io.Println()

	// Спрашиваем где сохранить файл
	savePath, err := c.io.ReadInput("Save to file (press Enter to skip): ")
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
	c.io.Println()

	return nil
}

func (c *Cli) displayCardData(card *models.CardData) error {
	c.io.Println("=== Card Data Details ===")
	c.io.Println()

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
	c.io.Println()

	return nil
}
