package crdt

import (
	"sync"

	"github.com/iudanet/gophkeeper/internal/models"
)

// LWWSet представляет Last-Write-Wins Element Set CRDT.
// Это структура данных, которая автоматически разрешает конфликты
// при репликации данных между несколькими узлами.
type LWWSet struct {
	elements map[string]*models.CRDTEntry // map[id]entry
	mu       sync.RWMutex                 // мьютекс для потокобезопасности
}

// NewLWWSet создает новый экземпляр LWW-Element-Set.
func NewLWWSet() *LWWSet {
	return &LWWSet{
		elements: make(map[string]*models.CRDTEntry),
	}
}

// Add добавляет новый элемент в set или обновляет существующий,
// если новая версия имеет больший timestamp.
// Возвращает true, если элемент был добавлен/обновлен.
func (s *LWWSet) Add(entry *models.CRDTEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.elements[entry.ID]

	// Если элемента нет - добавляем
	if !exists {
		s.elements[entry.ID] = entry.Clone()
		return true
	}

	// Если новая версия новее - обновляем
	if entry.IsNewerThan(existing) {
		s.elements[entry.ID] = entry.Clone()
		return true
	}

	// Существующая версия новее - не обновляем
	return false
}

// Update обновляет существующий элемент новыми данными.
// Это алиас для Add, так как логика одинаковая.
func (s *LWWSet) Update(entry *models.CRDTEntry) bool {
	return s.Add(entry)
}

// Remove помечает элемент как удаленный (soft delete).
// Физически элемент остается в set, но с флагом Deleted = true.
// Возвращает true, если элемент был помечен как удаленный.
func (s *LWWSet) Remove(entry *models.CRDTEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.elements[entry.ID]

	// Если элемента нет - добавляем как удаленный
	if !exists {
		deletedEntry := entry.Clone()
		deletedEntry.Deleted = true
		s.elements[entry.ID] = deletedEntry
		return true
	}

	// Если новая версия новее - обновляем и помечаем как удаленный
	if entry.IsNewerThan(existing) {
		deletedEntry := entry.Clone()
		deletedEntry.Deleted = true
		s.elements[entry.ID] = deletedEntry
		return true
	}

	return false
}

// Get возвращает элемент по ID.
// Возвращает nil, если элемент не найден или помечен как удаленный.
func (s *LWWSet) Get(id string) *models.CRDTEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.elements[id]
	if !exists || entry.Deleted {
		return nil
	}

	return entry.Clone()
}

// GetAll возвращает все неудаленные элементы.
func (s *LWWSet) GetAll() []*models.CRDTEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.CRDTEntry, 0, len(s.elements))
	for _, entry := range s.elements {
		if !entry.Deleted {
			result = append(result, entry.Clone())
		}
	}

	return result
}

// GetAllIncludingDeleted возвращает все элементы, включая удаленные.
// Используется для синхронизации с другими узлами.
func (s *LWWSet) GetAllIncludingDeleted() []*models.CRDTEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*models.CRDTEntry, 0, len(s.elements))
	for _, entry := range s.elements {
		result = append(result, entry.Clone())
	}

	return result
}

// Merge объединяет текущий set с другим set.
// Для каждого элемента применяется правило LWW (Last-Write-Wins):
// - Берется элемент с большим timestamp
// - При равных timestamp берется элемент с большим nodeID (для детерминизма)
// Операция коммутативна и идемпотентна.
func (s *LWWSet) Merge(other *LWWSet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	other.mu.RLock()
	defer other.mu.RUnlock()

	for id, otherEntry := range other.elements {
		existing, exists := s.elements[id]

		// Если элемента нет - добавляем
		if !exists {
			s.elements[id] = otherEntry.Clone()
			continue
		}

		// Если элемент из другого set новее - обновляем
		if otherEntry.IsNewerThan(existing) {
			s.elements[id] = otherEntry.Clone()
		}
	}
}

// Size возвращает количество неудаленных элементов в set.
func (s *LWWSet) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, entry := range s.elements {
		if !entry.Deleted {
			count++
		}
	}

	return count
}

// TotalSize возвращает общее количество элементов (включая удаленные).
func (s *LWWSet) TotalSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.elements)
}

// Contains проверяет наличие неудаленного элемента с заданным ID.
func (s *LWWSet) Contains(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.elements[id]
	return exists && !entry.Deleted
}

// Clear удаляет все элементы из set.
// Используется для очистки локального хранилища.
func (s *LWWSet) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.elements = make(map[string]*models.CRDTEntry)
}
