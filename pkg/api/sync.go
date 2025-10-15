package api

import "time"

// CRDTEntry представляет одну запись CRDT для синхронизации
type CRDTEntry struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	DataType  string    `json:"data_type"`
	Metadata  string    `json:"metadata"`
	Data      []byte    `json:"data"`
	Timestamp int64     `json:"timestamp"`
	Deleted   bool      `json:"deleted"`
}

// SyncRequest представляет запрос на синхронизацию от клиента
type SyncRequest struct {
	Entries []CRDTEntry `json:"entries"`
	Since   int64       `json:"since"`
}

// SyncResponse представляет ответ сервера на синхронизацию
type SyncResponse struct {
	Entries          []CRDTEntry `json:"entries"`           // Изменения от сервера
	CurrentTimestamp int64       `json:"current_timestamp"` // Текущий Lamport clock сервера
	Conflicts        int         `json:"conflicts"`         // Количество разрешенных конфликтов
}
