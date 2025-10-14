package models

import "time"

// CRDTEntry представляет элемент в CRDT (Conflict-free Replicated Data Type).
// Используется для синхронизации данных между несколькими клиентами
// с автоматическим разрешением конфликтов.
type CRDTEntry struct {
	// ID уникальный идентификатор записи (UUID)
	ID string `json:"id"`

	// UserID идентификатор владельца записи
	UserID string `json:"user_id"`

	// Type тип данных: "credential", "text", "binary", "card"
	Type string `json:"type"`

	// Data зашифрованные данные (JSON сериализованный и зашифрованный объект)
	Data []byte `json:"data"`

	// Metadata зашифрованные метаданные
	Metadata []byte `json:"metadata"`

	// Version монотонно растущая версия записи
	Version int64 `json:"version"`

	// Timestamp Lamport timestamp для упорядочивания событий
	Timestamp int64 `json:"timestamp"`

	// NodeID идентификатор узла (клиента), создавшего эту версию
	NodeID string `json:"node_id"`

	// Deleted флаг soft delete (true = запись удалена)
	Deleted bool `json:"deleted"`

	// CreatedAt время создания записи (для информации)
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt время последнего обновления (для информации)
	UpdatedAt time.Time `json:"updated_at"`
}

// DataType константы для типов данных
const (
	DataTypeCredential = "credential"
	DataTypeText       = "text"
	DataTypeBinary     = "binary"
	DataTypeCard       = "card"
)

// IsNewerThan сравнивает две CRDT записи и определяет, какая из них новее.
// Согласно алгоритму LWW (Last-Write-Wins):
// 1. Сначала сравнивается Timestamp (больший выигрывает)
// 2. При равных Timestamp сравнивается NodeID (лексикографически)
// Возвращает true, если current запись новее, чем other.
func (e *CRDTEntry) IsNewerThan(other *CRDTEntry) bool {
	if e.Timestamp > other.Timestamp {
		return true
	}
	if e.Timestamp < other.Timestamp {
		return false
	}
	// Timestamps равны - сравниваем NodeID для детерминизма
	return e.NodeID > other.NodeID
}

// Clone создает глубокую копию CRDT записи
func (e *CRDTEntry) Clone() *CRDTEntry {
	data := make([]byte, len(e.Data))
	copy(data, e.Data)

	metadata := make([]byte, len(e.Metadata))
	copy(metadata, e.Metadata)

	return &CRDTEntry{
		ID:        e.ID,
		UserID:    e.UserID,
		Type:      e.Type,
		Data:      data,
		Metadata:  metadata,
		Version:   e.Version,
		Timestamp: e.Timestamp,
		NodeID:    e.NodeID,
		Deleted:   e.Deleted,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}
