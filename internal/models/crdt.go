package models

import "time"

// CRDTEntry представляет элемент в CRDT (Conflict-free Replicated Data Type).
// Используется для синхронизации данных между несколькими клиентами
// с автоматическим разрешением конфликтов.
type CRDTEntry struct {
	CreatedAt time.Time `json:"created_at"` // CreatedAt время создания записи (для информации)

	UpdatedAt time.Time `json:"updated_at"` // UpdatedAt время последнего обновления (для информации)
	ID        string    `json:"id"`         // ID уникальный идентификатор записи (UUID)
	UserID    string    `json:"user_id"`    // UserID идентификатор владельца записи
	Type      string    `json:"type"`       // Type тип данных: "credential", "text", "binary", "card"
	NodeID    string    `json:"node_id"`    // NodeID идентификатор узла (клиента), создавшего эту версию
	Data      []byte    `json:"data"`       // Data зашифрованные данные (JSON сериализованный и зашифрованный объект)
	Metadata  []byte    `json:"metadata"`   // Metadata зашифрованные метаданные
	Version   int64     `json:"version"`    // Version монотонно растущая версия записи
	Timestamp int64     `json:"timestamp"`  // Timestamp Lamport timestamp для упорядочивания событий
	Deleted   bool      `json:"deleted"`    // Deleted флаг soft delete (true = запись удалена)
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
