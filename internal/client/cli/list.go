package cli

import (
	"context"
	"fmt"
)

func (c *Cli) runList(ctx context.Context, args []string) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. Usage: gophkeeper list <credentials|text|binary|card>")
	}

	dataType := args[0]

	switch dataType {
	case "credentials", "credential":
		return c.runListCredentials(ctx)
	case "text":
		return c.runListText(ctx)
	case "binary":
		return c.runListBinary(ctx)
	case "card", "cards":
		return c.runListCards(ctx)
	default:
		return fmt.Errorf("unknown data type: %s. Use: credentials, text, binary, or card", dataType)
	}
}

func (c *Cli) runListCredentials(ctx context.Context) error {
	c.io.Println("=== Saved Credentials ===")

	// Получаем список credentials через data service
	credentials, err := c.dataService.ListCredentials(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	if len(credentials) == 0 {
		c.io.Println("No credentials found.")
		c.io.Println()
		c.io.Println("Use 'gophkeeper add credential' to add your first credential.")
		return nil
	}

	fmt.Printf("Found %d credential(s):\n", len(credentials))
	c.io.Println()

	for i, cred := range credentials {
		fmt.Printf("%d. %s\n", i+1, cred.Name)
		fmt.Printf("   ID:    %s\n", cred.ID)
		fmt.Printf("   Login: %s\n", cred.Login)
		if cred.URL != "" {
			fmt.Printf("   URL:   %s\n", cred.URL)
		}
		if cred.Notes != "" {
			fmt.Printf("   Notes: %s\n", cred.Notes)
		}
		c.io.Println()
	}

	c.io.Println("Note: Passwords are hidden for security. Use 'gophkeeper get <id>' to view full details.")

	return nil
}

func (c *Cli) runListText(ctx context.Context) error {
	c.io.Println("=== Saved Text Data ===")

	// Получаем список text data через data service
	textData, err := c.dataService.ListTextData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list text data: %w", err)
	}

	if len(textData) == 0 {
		c.io.Println("No text data found.")
		c.io.Println()
		c.io.Println("Use 'gophkeeper add text' to add your first text entry.")
		return nil
	}

	fmt.Printf("Found %d text entry(ies):\n", len(textData))
	c.io.Println()

	for i, text := range textData {
		fmt.Printf("%d. %s\n", i+1, text.Name)
		fmt.Printf("   ID:      %s\n", text.ID)
		// Показываем первые 50 символов содержимого
		preview := text.Content
		if len(preview) > 50 {
			preview = preview[:50] + "..."
		}
		fmt.Printf("   Preview: %s\n", preview)
		c.io.Println()
	}

	c.io.Println("Use 'gophkeeper get <id>' to view full content.")

	return nil
}

func (c *Cli) runListBinary(ctx context.Context) error {
	c.io.Println("=== Saved Binary Data ===")

	// Получаем список binary data через data service
	binaryData, err := c.dataService.ListBinaryData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list binary data: %w", err)
	}

	if len(binaryData) == 0 {
		c.io.Println("No binary data found.")
		c.io.Println()
		c.io.Println("Use 'gophkeeper add binary' to add your first binary file.")
		return nil
	}

	fmt.Printf("Found %d binary file(s):\n", len(binaryData))
	c.io.Println()

	for i, binary := range binaryData {
		fmt.Printf("%d. %s\n", i+1, binary.Name)
		fmt.Printf("   ID:       %s\n", binary.ID)
		if filename, ok := binary.Metadata.CustomFields["filename"]; ok {
			fmt.Printf("   Filename: %s\n", filename)
		}
		fmt.Printf("   Size:     %d bytes\n", len(binary.Data))
		if binary.MimeType != "" {
			fmt.Printf("   Type:     %s\n", binary.MimeType)
		}
		c.io.Println()
	}

	c.io.Println("Use 'gophkeeper get <id>' to download the file.")

	return nil
}

func (c *Cli) runListCards(ctx context.Context) error {
	c.io.Println("=== Saved Card Data ===")

	// Получаем список card data через data service
	cardData, err := c.dataService.ListCardData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list card data: %w", err)
	}

	if len(cardData) == 0 {
		c.io.Println("No card data found.")
		c.io.Println()
		c.io.Println("Use 'gophkeeper add card' to add your first card.")
		return nil
	}

	fmt.Printf("Found %d card(s):\n", len(cardData))
	c.io.Println()

	for i, card := range cardData {
		fmt.Printf("%d. %s\n", i+1, card.Name)
		fmt.Printf("   ID:     %s\n", card.ID)
		// Маскируем номер карты (показываем только последние 4 цифры)
		maskedNumber := maskCardNumber(card.Number)
		fmt.Printf("   Number: %s\n", maskedNumber)
		if card.Holder != "" {
			fmt.Printf("   Holder: %s\n", card.Holder)
		}
		if card.Expiry != "" {
			fmt.Printf("   Expiry: %s\n", card.Expiry)
		}
		c.io.Println()
	}

	c.io.Println("Note: Card details are masked. Use 'gophkeeper get <id>' to view full details.")

	return nil
}
