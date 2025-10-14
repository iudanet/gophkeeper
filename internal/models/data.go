package models

// Metadata представляет метаданные для любого типа данных.
// Содержит информацию для организации и поиска данных:
// теги, категории, избранное, заметки и кастомные поля.
type Metadata struct {
	// Tags теги для поиска и группировки (например, "work", "personal")
	Tags []string `json:"tags"`

	// Category категория данных (например, "banking", "social", "work")
	Category string `json:"category"`

	// Favorite флаг избранного для быстрого доступа
	Favorite bool `json:"favorite"`

	// Notes дополнительные заметки пользователя
	Notes string `json:"notes"`

	// CustomFields произвольные кастомные поля (ключ-значение)
	// Позволяет пользователю добавлять любые дополнительные метаданные
	CustomFields map[string]string `json:"custom_fields"`
}

// Credential представляет учетные данные (логин/пароль).
// Используется для хранения паролей от сайтов, приложений и сервисов.
type Credential struct {
	// ID уникальный идентификатор записи (UUID)
	ID string `json:"id"`

	// Name название учетной записи (например, "GitHub", "Gmail")
	Name string `json:"name"`

	// Login логин или email
	Login string `json:"login"`

	// Password пароль
	Password string `json:"password"`

	// URL опциональный URL сайта или сервиса
	URL string `json:"url"`

	// Notes опциональные заметки (например, "рабочий аккаунт")
	Notes string `json:"notes"`

	// Metadata метаданные записи (теги, категория, избранное и т.д.)
	Metadata Metadata `json:"metadata"`
}

// TextData представляет произвольные текстовые данные.
// Используется для хранения заметок, секретных ключей, recovery-фраз и т.д.
type TextData struct {
	// ID уникальный идентификатор записи (UUID)
	ID string `json:"id"`

	// Name название записи
	Name string `json:"name"`

	// Content текстовое содержимое
	Content string `json:"content"`

	// Metadata метаданные записи
	Metadata Metadata `json:"metadata"`
}

// BinaryData представляет бинарные данные (файлы).
// Используется для хранения документов, фотографий, сертификатов и т.д.
type BinaryData struct {
	// ID уникальный идентификатор записи (UUID)
	ID string `json:"id"`

	// Name название файла
	Name string `json:"name"`

	// Data бинарные данные файла
	Data []byte `json:"data"`

	// MimeType MIME-тип файла (например, "image/jpeg", "application/pdf")
	MimeType string `json:"mime_type"`

	// Metadata метаданные записи
	Metadata Metadata `json:"metadata"`
}

// CardData представляет данные банковской карты.
// Используется для хранения информации о банковских картах.
type CardData struct {
	// ID уникальный идентификатор записи (UUID)
	ID string `json:"id"`

	// Name название карты (например, "Visa Gold", "Сбербанк")
	Name string `json:"name"`

	// Number номер карты (16 цифр)
	Number string `json:"number"`

	// Holder имя держателя карты (как на карте)
	Holder string `json:"holder"`

	// Expiry срок действия в формате MM/YY
	Expiry string `json:"expiry"`

	// CVV CVV/CVC код (3-4 цифры)
	CVV string `json:"cvv"`

	// PIN опциональный PIN-код карты
	PIN string `json:"pin"`

	// Metadata метаданные записи
	Metadata Metadata `json:"metadata"`
}
