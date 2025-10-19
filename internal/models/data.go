package models

// Metadata представляет метаданные для любого типа данных.
// Содержит информацию для организации и поиска данных:
// теги, категории, избранное, заметки и кастомные поля.
type Metadata struct {
	// CustomFields произвольные кастомные поля (ключ-значение)
	// Позволяет пользователю добавлять любые дополнительные метаданные
	CustomFields map[string]string `json:"custom_fields"`
	Category     string            `json:"category"` // Category категория данных (например, "banking", "social", "work")
	Notes        string            `json:"notes"`    // Notes дополнительные заметки пользователя
	Tags         []string          `json:"tags"`     // Tags теги для поиска и группировки (например, "work", "personal")
	Favorite     bool              `json:"favorite"` // Favorite флаг избранного для быстрого доступа
}

// Credential представляет учетные данные (логин/пароль).
// Используется для хранения паролей от сайтов, приложений и сервисов.
type Credential struct {
	ID       string   `json:"id"`       // ID уникальный идентификатор записи (UUID)
	Name     string   `json:"name"`     // Name название учетной записи (например, "GitHub", "Gmail")
	Login    string   `json:"login"`    // Login логин или email
	Password string   `json:"password"` // Password пароль
	URL      string   `json:"url"`      // URL опциональный URL сайта или сервиса
	Notes    string   `json:"notes"`    // Notes опциональные заметки (например, "рабочий аккаунт")
	Metadata Metadata `json:"metadata"` // Metadata метаданные записи (теги, категория, избранное и т.д.)
}

// TextData представляет произвольные текстовые данные.
// Используется для хранения заметок, секретных ключей, recovery-фраз и т.д.
type TextData struct {
	ID       string   `json:"id"`       // ID уникальный идентификатор записи (UUID)
	Name     string   `json:"name"`     // Name название записи
	Content  string   `json:"content"`  // Content текстовое содержимое
	Metadata Metadata `json:"metadata"` //  Metadata метаданные записи
}

// BinaryData представляет бинарные данные (файлы).
// Используется для хранения документов, фотографий, сертификатов и т.д.
type BinaryData struct {
	ID       string   `json:"id"`        // ID уникальный идентификатор записи (UUID)
	Name     string   `json:"name"`      // Name название файла
	MimeType string   `json:"mime_type"` // MimeType MIME-тип файла (например, "image/jpeg", "application/pdf")
	Data     []byte   `json:"data"`      // Data бинарные данные файла
	Metadata Metadata `json:"metadata"`  // Metadata метаданные записи
}

// CardData представляет данные банковской карты.
// Используется для хранения информации о банковских картах.
type CardData struct {
	ID       string   `json:"id"`       // ID уникальный идентификатор записи (UUID)
	Name     string   `json:"name"`     // Name название карты (например, "Visa Gold", "Сбербанк")
	Number   string   `json:"number"`   // Number номер карты (16 цифр)
	Holder   string   `json:"holder"`   // Holder имя держателя карты (как на карте)
	Expiry   string   `json:"expiry"`   // Expiry срок действия в формате MM/YY
	CVV      string   `json:"cvv"`      // CVV CVV/CVC код (3-4 цифры)
	PIN      string   `json:"pin"`      // PIN опциональный PIN-код карты
	Metadata Metadata `json:"metadata"` // Metadata метаданные записи
}
