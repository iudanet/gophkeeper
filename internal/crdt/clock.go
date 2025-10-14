package crdt

import (
	"sync"

	"github.com/google/uuid"
)

// LamportClock представляет логические часы Лампорта для упорядочивания событий
// в распределенной системе без необходимости синхронизации физического времени.
type LamportClock struct {
	counter int64      // монотонно возрастающий счетчик
	nodeID  string     // уникальный идентификатор узла
	mu      sync.Mutex // мьютекс для потокобезопасности
}

// NewLamportClock создает новый экземпляр логических часов Лампорта
// с уникальным идентификатором узла (UUID).
func NewLamportClock() *LamportClock {
	return &LamportClock{
		counter: 0,
		nodeID:  uuid.New().String(),
	}
}

// NewLamportClockWithNodeID создает новый экземпляр логических часов Лампорта
// с заданным идентификатором узла. Используется для тестирования или восстановления состояния.
func NewLamportClockWithNodeID(nodeID string) *LamportClock {
	return &LamportClock{
		counter: 0,
		nodeID:  nodeID,
	}
}

// Tick увеличивает счетчик и возвращает новое значение timestamp.
// Используется при создании нового локального события.
func (lc *LamportClock) Tick() int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.counter++
	return lc.counter
}

// Update обновляет счетчик на основе полученного удаленного timestamp.
// Используется при получении события от другого узла для синхронизации.
// Согласно алгоритму Лампорта: counter = max(local_counter, remote_timestamp) + 1
func (lc *LamportClock) Update(remoteTimestamp int64) int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if remoteTimestamp > lc.counter {
		lc.counter = remoteTimestamp
	}
	lc.counter++

	return lc.counter
}

// GetTimestamp возвращает текущее значение счетчика без его изменения.
// Используется для чтения текущего состояния часов.
func (lc *LamportClock) GetTimestamp() int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	return lc.counter
}

// GetNodeID возвращает уникальный идентификатор узла.
func (lc *LamportClock) GetNodeID() string {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	return lc.nodeID
}

// SetTimestamp устанавливает счетчик в заданное значение.
// Используется для восстановления состояния часов (например, после перезапуска).
func (lc *LamportClock) SetTimestamp(timestamp int64) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	lc.counter = timestamp
}
