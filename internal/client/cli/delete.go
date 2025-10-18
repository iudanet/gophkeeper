package cli

import (
	"context"
	"fmt"

	"github.com/iudanet/gophkeeper/internal/models"
)

func (c *Cli) runDelete(ctx context.Context, args []string) error {
	// Проверяем наличие ID
	if len(args) == 0 {
		return fmt.Errorf("missing entry ID. Usage: gophkeeper delete <id>")
	}

	entryID := args[0]

	// Определяем тип entry и удаляем
	// Пробуем как credential
	cred, err := c.dataService.GetCredential(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.deleteCredential(ctx, entryID, cred)
	}

	// Пробуем как text
	text, err := c.dataService.GetTextData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.deleteTextData(ctx, entryID, text)
	}

	// Пробуем как binary
	binary, err := c.dataService.GetBinaryData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.deleteBinaryData(ctx, entryID, binary)
	}

	// Пробуем как card
	card, err := c.dataService.GetCardData(ctx, entryID, c.encryptionKey)
	if err == nil {
		return c.deleteCardData(ctx, entryID, card)
	}

	return fmt.Errorf("entry not found with ID: %s", entryID)
}

func (c *Cli) deleteCredential(ctx context.Context, id string, credential *models.Credential) error {

	c.io.Println("=== Delete Credential ===")
	c.io.Println()
	c.io.Println("About to delete:")
	c.io.Printf("  Name:  %s\n", credential.Name)
	c.io.Printf("  Login: %s\n", credential.Login)
	if credential.URL != "" {
		c.io.Printf("  URL:   %s\n", credential.URL)
	}
	c.io.Println()

	confirm, err := c.io.ReadInput("Are you sure you want to delete this credential? (yes/no): ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" && confirm != "y" {
		c.io.Println()
		c.io.Println("Deletion cancelled.")
		return nil
	}

	if err := c.dataService.DeleteCredential(ctx, id, c.authData.NodeID); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Credential deleted successfully!")
	c.io.Println()
	c.io.Println("Note: Run 'gophkeeper sync' to sync with server.")

	return nil
}

func (c *Cli) deleteTextData(ctx context.Context, id string, textData *models.TextData) error {

	c.io.Println("=== Delete Text Data ===")
	c.io.Println()
	c.io.Println("About to delete:")
	c.io.Printf("  Name: %s\n", textData.Name)
	preview := textData.Content
	if len(preview) > 50 {
		preview = preview[:50] + "..."
	}
	c.io.Printf("  Preview: %s\n", preview)
	c.io.Println()

	confirm, err := c.io.ReadInput("Are you sure you want to delete this text data? (yes/no): ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" && confirm != "y" {
		c.io.Println()
		c.io.Println("Deletion cancelled.")
		return nil
	}

	if err := c.dataService.DeleteTextData(ctx, id, c.authData.NodeID); err != nil {
		return fmt.Errorf("failed to delete text data: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Text data deleted successfully!")
	c.io.Println()
	c.io.Println("Note: Run 'gophkeeper sync' to sync with server.")

	return nil
}

func (c *Cli) deleteBinaryData(ctx context.Context, id string, binaryData *models.BinaryData) error {

	c.io.Println("=== Delete Binary Data ===")
	c.io.Println()
	c.io.Println("About to delete:")
	c.io.Printf("  Name:     %s\n", binaryData.Name)
	if filename, ok := binaryData.Metadata.CustomFields["filename"]; ok {
		c.io.Printf("  Filename: %s\n", filename)
	}
	c.io.Printf("  Size:     %d bytes\n", len(binaryData.Data))
	c.io.Println()

	confirm, err := c.io.ReadInput("Are you sure you want to delete this file? (yes/no): ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" && confirm != "y" {
		c.io.Println()
		c.io.Println("Deletion cancelled.")
		return nil
	}

	if err := c.dataService.DeleteBinaryData(ctx, id, c.authData.NodeID); err != nil {
		return fmt.Errorf("failed to delete binary data: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ File deleted successfully!")
	c.io.Println()
	c.io.Println("Note: Run 'gophkeeper sync' to sync with server.")

	return nil
}

func (c *Cli) deleteCardData(ctx context.Context, id string, cardData *models.CardData) error {

	c.io.Println("=== Delete Card Data ===")
	c.io.Println()
	c.io.Println("About to delete:")
	c.io.Printf("  Name:   %s\n", cardData.Name)
	maskedNumber := maskCardNumber(cardData.Number)
	c.io.Printf("  Number: %s\n", maskedNumber)
	if cardData.Holder != "" {
		c.io.Printf("  Holder: %s\n", cardData.Holder)
	}
	c.io.Println()

	confirm, err := c.io.ReadInput("Are you sure you want to delete this card? (yes/no): ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirm != "yes" && confirm != "y" {
		c.io.Println()
		c.io.Println("Deletion cancelled.")
		return nil
	}

	if err := c.dataService.DeleteCardData(ctx, id, c.authData.NodeID); err != nil {
		return fmt.Errorf("failed to delete card data: %w", err)
	}

	c.io.Println()
	c.io.Println("✓ Card deleted successfully!")
	c.io.Println()
	c.io.Println("Note: Run 'gophkeeper sync' to sync with server.")

	return nil
}
