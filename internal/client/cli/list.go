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
	credentials, err := c.dataService.ListCredentials(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list credentials: %w", err)
	}

	return c.printTemplate(credentialsListTemplate, credentials)
}

func (c *Cli) runListText(ctx context.Context) error {
	textData, err := c.dataService.ListTextData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list text data: %w", err)
	}

	return c.printTemplate(textDataListTemplate, textData)
}

func (c *Cli) runListBinary(ctx context.Context) error {
	binaryData, err := c.dataService.ListBinaryData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list binary data: %w", err)
	}

	return c.printTemplate(binaryDataListTemplate, binaryData)
}

func (c *Cli) runListCards(ctx context.Context) error {
	cardData, err := c.dataService.ListCardData(ctx, c.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to list card data: %w", err)
	}

	// Создаем слайс копий карточек с замаскированным номером
	type CardView struct {
		ID     string
		Name   string
		Number string
		Holder string
		Expiry string
	}

	cardsView := make([]CardView, 0, len(cardData))
	for _, card := range cardData {
		cardsView = append(cardsView, CardView{
			ID:     card.ID,
			Name:   card.Name,
			Number: maskCardNumber(card.Number),
			Holder: card.Holder,
			Expiry: card.Expiry,
		})
	}

	return c.printTemplate(cardDataListTemplate, cardsView)
}

// maskCardNumber masks a card number showing only the last 4 digits
func maskCardNumber(number string) string {
	if len(number) < 4 {
		return "****-****-****-****" // Полностью маскируем короткие номера
	}
	return "****-****-****-" + number[len(number)-4:]
}
