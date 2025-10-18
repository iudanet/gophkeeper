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
	return c.printTemplate(credentialTemplate, credential)
}

func (c *Cli) displayTextData(textData *models.TextData) error {
	return c.printTemplate(textDataTemplate, textData)
}

func (c *Cli) displayBinaryData(binaryData *models.BinaryData) error {
	err := c.printTemplate(binaryDataTemplate, binaryData)
	if err != nil {
		return fmt.Errorf("failed to print template: %w", err)
	}

	savePath, err := c.io.ReadInput("Save to file (press Enter to skip): ")
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if savePath != "" {
		if err := os.WriteFile(savePath, binaryData.Data, 0600); err != nil {
			return fmt.Errorf("failed to save file: %w", err)
		}
		c.io.Printf("✓ File saved to: %s\n", savePath)
	}
	c.io.Println()

	return nil
}

func (c *Cli) displayCardData(card *models.CardData) error {
	return c.printTemplate(cardDataTemplate, card)
}
