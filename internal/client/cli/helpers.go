package cli

// maskCardNumber masks a card number showing only the last 4 digits
func maskCardNumber(number string) string {
	if len(number) < 4 {
		return "****-****-****-****" // Полностью маскируем короткие номера
	}
	return "****-****-****-" + number[len(number)-4:]
}
