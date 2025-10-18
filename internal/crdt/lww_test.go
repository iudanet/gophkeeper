package crdt

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iudanet/gophkeeper/internal/models"
)

func createTestEntry(id, userID, nodeID string, timestamp int64, deleted bool) *models.CRDTEntry {
	return &models.CRDTEntry{
		ID:        id,
		UserID:    userID,
		Type:      models.DataTypeCredential,
		Data:      []byte("encrypted data"),
		Metadata:  []byte("encrypted metadata"),
		Version:   1,
		Timestamp: timestamp,
		NodeID:    nodeID,
		Deleted:   deleted,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestNewLWWSet(t *testing.T) {
	set := NewLWWSet()

	require.NotNil(t, set)
	assert.Equal(t, 0, set.Size(), "New set should be empty")
	assert.Equal(t, 0, set.TotalSize(), "New set should have no elements")
}

func TestLWWSet_Add(t *testing.T) {
	tests := []struct {
		entry         *models.CRDTEntry
		name          string
		expectedSize  int
		expectedAdded bool
	}{
		{
			name:          "add new entry",
			entry:         createTestEntry("id1", "user1", "node1", 10, false),
			expectedSize:  1,
			expectedAdded: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewLWWSet()
			added := set.Add(tt.entry)

			assert.Equal(t, tt.expectedAdded, added, "Add should return correct value")
			assert.Equal(t, tt.expectedSize, set.Size(), "Size should match expected")
			assert.True(t, set.Contains(tt.entry.ID), "Entry should be in set")
		})
	}
}

func TestLWWSet_Add_UpdateNewerEntry(t *testing.T) {
	set := NewLWWSet()

	// Добавляем начальную запись
	entry1 := createTestEntry("id1", "user1", "node1", 10, false)
	added := set.Add(entry1)
	assert.True(t, added, "First add should succeed")
	assert.Equal(t, 1, set.Size())

	// Обновляем более новой версией (больший timestamp)
	entry2 := createTestEntry("id1", "user1", "node1", 20, false)
	entry2.Data = []byte("updated data")
	updated := set.Add(entry2)

	assert.True(t, updated, "Update with newer timestamp should succeed")
	assert.Equal(t, 1, set.Size(), "Size should remain 1")

	// Проверяем, что данные обновились
	retrieved := set.Get("id1")
	require.NotNil(t, retrieved)
	assert.Equal(t, []byte("updated data"), retrieved.Data)
	assert.Equal(t, int64(20), retrieved.Timestamp)
}

func TestLWWSet_Add_IgnoreOlderEntry(t *testing.T) {
	set := NewLWWSet()

	// Добавляем новую запись
	entry1 := createTestEntry("id1", "user1", "node1", 20, false)
	set.Add(entry1)

	// Пытаемся добавить старую версию (меньший timestamp)
	entry2 := createTestEntry("id1", "user1", "node1", 10, false)
	entry2.Data = []byte("old data")
	updated := set.Add(entry2)

	assert.False(t, updated, "Update with older timestamp should be ignored")

	// Проверяем, что данные не изменились
	retrieved := set.Get("id1")
	require.NotNil(t, retrieved)
	assert.NotEqual(t, []byte("old data"), retrieved.Data)
	assert.Equal(t, int64(20), retrieved.Timestamp)
}

func TestLWWSet_Add_ConflictResolution_SameTimestamp(t *testing.T) {
	set := NewLWWSet()

	// Добавляем запись с nodeID = "node1"
	entry1 := createTestEntry("id1", "user1", "node1", 10, false)
	set.Add(entry1)

	// Пытаемся добавить запись с тем же timestamp, но nodeID = "node2" (больше лексикографически)
	entry2 := createTestEntry("id1", "user1", "node2", 10, false)
	entry2.Data = []byte("data from node2")
	updated := set.Add(entry2)

	assert.True(t, updated, "Entry with greater nodeID should win")

	retrieved := set.Get("id1")
	require.NotNil(t, retrieved)
	assert.Equal(t, []byte("data from node2"), retrieved.Data)
	assert.Equal(t, "node2", retrieved.NodeID)
}

func TestLWWSet_Remove(t *testing.T) {
	set := NewLWWSet()

	// Добавляем запись
	entry1 := createTestEntry("id1", "user1", "node1", 10, false)
	set.Add(entry1)
	assert.True(t, set.Contains("id1"))

	// Удаляем запись (более новый timestamp)
	entry2 := createTestEntry("id1", "user1", "node1", 20, false)
	removed := set.Remove(entry2)

	assert.True(t, removed, "Remove should succeed")
	assert.False(t, set.Contains("id1"), "Entry should be marked as deleted")
	assert.Equal(t, 0, set.Size(), "Size should be 0 (excluding deleted)")
	assert.Equal(t, 1, set.TotalSize(), "TotalSize should be 1 (including deleted)")

	// Get не должен возвращать удаленную запись
	retrieved := set.Get("id1")
	assert.Nil(t, retrieved, "Get should return nil for deleted entry")
}

func TestLWWSet_Remove_IgnoreOlderTimestamp(t *testing.T) {
	set := NewLWWSet()

	// Добавляем запись
	entry1 := createTestEntry("id1", "user1", "node1", 20, false)
	set.Add(entry1)

	// Пытаемся удалить с более старым timestamp
	entry2 := createTestEntry("id1", "user1", "node1", 10, false)
	removed := set.Remove(entry2)

	assert.False(t, removed, "Remove with older timestamp should be ignored")
	assert.True(t, set.Contains("id1"), "Entry should still exist")
}

func TestLWWSet_Get(t *testing.T) {
	set := NewLWWSet()

	// Попытка получить несуществующий элемент
	retrieved := set.Get("nonexistent")
	assert.Nil(t, retrieved)

	// Добавляем элемент
	entry := createTestEntry("id1", "user1", "node1", 10, false)
	set.Add(entry)

	// Получаем элемент
	retrieved = set.Get("id1")
	require.NotNil(t, retrieved)
	assert.Equal(t, "id1", retrieved.ID)
	assert.Equal(t, int64(10), retrieved.Timestamp)

	// Проверяем, что возвращается копия
	retrieved.Data = []byte("modified")
	retrieved2 := set.Get("id1")
	assert.NotEqual(t, []byte("modified"), retrieved2.Data, "Should return a copy")
}

func TestLWWSet_GetAll(t *testing.T) {
	set := NewLWWSet()

	// Пустой set
	all := set.GetAll()
	assert.Empty(t, all)

	// Добавляем несколько элементов
	set.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set.Add(createTestEntry("id2", "user1", "node1", 20, false))
	set.Add(createTestEntry("id3", "user1", "node1", 30, true)) // deleted

	all = set.GetAll()
	assert.Len(t, all, 2, "GetAll should return only non-deleted entries")

	// Проверяем, что удаленная запись не включена
	for _, entry := range all {
		assert.False(t, entry.Deleted)
	}
}

func TestLWWSet_GetAllIncludingDeleted(t *testing.T) {
	set := NewLWWSet()

	set.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set.Add(createTestEntry("id2", "user1", "node1", 20, false))
	set.Add(createTestEntry("id3", "user1", "node1", 30, true)) // deleted

	all := set.GetAllIncludingDeleted()
	assert.Len(t, all, 3, "GetAllIncludingDeleted should return all entries")
}

func TestLWWSet_Merge_EmptySets(t *testing.T) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	set1.Merge(set2)

	assert.Equal(t, 0, set1.Size())
	assert.Equal(t, 0, set2.Size())
}

func TestLWWSet_Merge_AddNewEntries(t *testing.T) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	// set1 имеет entry1
	set1.Add(createTestEntry("id1", "user1", "node1", 10, false))

	// set2 имеет entry2
	set2.Add(createTestEntry("id2", "user1", "node2", 20, false))

	// Merge
	set1.Merge(set2)

	// set1 должен содержать оба элемента
	assert.Equal(t, 2, set1.Size())
	assert.True(t, set1.Contains("id1"))
	assert.True(t, set1.Contains("id2"))
}

func TestLWWSet_Merge_ResolveConflicts_NewerWins(t *testing.T) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	// set1 имеет старую версию
	entry1 := createTestEntry("id1", "user1", "node1", 10, false)
	entry1.Data = []byte("old data")
	set1.Add(entry1)

	// set2 имеет новую версию
	entry2 := createTestEntry("id1", "user1", "node2", 20, false)
	entry2.Data = []byte("new data")
	set2.Add(entry2)

	// Merge
	set1.Merge(set2)

	// set1 должен содержать новую версию
	retrieved := set1.Get("id1")
	require.NotNil(t, retrieved)
	assert.Equal(t, []byte("new data"), retrieved.Data)
	assert.Equal(t, int64(20), retrieved.Timestamp)
}

func TestLWWSet_Merge_Commutativity(t *testing.T) {
	// Создаем два set с разными данными
	set1A := NewLWWSet()
	set1A.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set1A.Add(createTestEntry("id2", "user1", "node1", 30, false))

	set2A := NewLWWSet()
	set2A.Add(createTestEntry("id1", "user1", "node2", 20, false))
	set2A.Add(createTestEntry("id3", "user1", "node2", 40, false))

	// Копируем для второго теста
	set1B := NewLWWSet()
	set1B.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set1B.Add(createTestEntry("id2", "user1", "node1", 30, false))

	set2B := NewLWWSet()
	set2B.Add(createTestEntry("id1", "user1", "node2", 20, false))
	set2B.Add(createTestEntry("id3", "user1", "node2", 40, false))

	// Merge в разном порядке
	set1A.Merge(set2A) // set1 <- set2
	set2B.Merge(set1B) // set2 <- set1

	// Результат должен быть одинаковым
	assert.Equal(t, set1A.Size(), set2B.Size())

	// Проверяем, что содержимое одинаковое
	for _, id := range []string{"id1", "id2", "id3"} {
		entry1 := set1A.Get(id)
		entry2 := set2B.Get(id)

		if entry1 == nil && entry2 == nil {
			continue
		}

		require.NotNil(t, entry1)
		require.NotNil(t, entry2)
		assert.Equal(t, entry1.Timestamp, entry2.Timestamp)
		assert.Equal(t, entry1.NodeID, entry2.NodeID)
	}
}

func TestLWWSet_Merge_Idempotency(t *testing.T) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	set1.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set2.Add(createTestEntry("id2", "user1", "node2", 20, false))

	// Первый merge
	set1.Merge(set2)
	size1 := set1.Size()

	// Повторный merge с тем же set
	set1.Merge(set2)
	size2 := set1.Size()

	// Размер не должен измениться
	assert.Equal(t, size1, size2, "Merge should be idempotent")
}

func TestLWWSet_Size(t *testing.T) {
	set := NewLWWSet()

	assert.Equal(t, 0, set.Size())

	set.Add(createTestEntry("id1", "user1", "node1", 10, false))
	assert.Equal(t, 1, set.Size())

	set.Add(createTestEntry("id2", "user1", "node1", 20, false))
	assert.Equal(t, 2, set.Size())

	// Добавление удаленного элемента
	set.Add(createTestEntry("id3", "user1", "node1", 30, true))
	assert.Equal(t, 2, set.Size(), "Deleted entry should not count")
	assert.Equal(t, 3, set.TotalSize(), "TotalSize should include deleted")
}

func TestLWWSet_Contains(t *testing.T) {
	set := NewLWWSet()

	assert.False(t, set.Contains("id1"))

	set.Add(createTestEntry("id1", "user1", "node1", 10, false))
	assert.True(t, set.Contains("id1"))

	// Удаляем элемент
	set.Remove(createTestEntry("id1", "user1", "node1", 20, false))
	assert.False(t, set.Contains("id1"), "Contains should return false for deleted entry")
}

func TestLWWSet_Clear(t *testing.T) {
	set := NewLWWSet()

	set.Add(createTestEntry("id1", "user1", "node1", 10, false))
	set.Add(createTestEntry("id2", "user1", "node1", 20, false))
	assert.Equal(t, 2, set.Size())

	set.Clear()
	assert.Equal(t, 0, set.Size())
	assert.Equal(t, 0, set.TotalSize())
	assert.False(t, set.Contains("id1"))
	assert.False(t, set.Contains("id2"))
}

func TestLWWSet_ConcurrentAdd(t *testing.T) {
	set := NewLWWSet()
	goroutines := 100
	entriesPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < entriesPerGoroutine; j++ {
				id := goroutineID*entriesPerGoroutine + j
				idStr := strconv.Itoa(id)              // Преобразуем в читаемую строку с цифрами
				nodeIDStr := strconv.Itoa(goroutineID) // Аналогично для nodeID

				entry := createTestEntry(
					idStr,
					"user1",
					nodeIDStr,
					int64(id),
					false,
				)
				set.Add(entry)
			}
		}(i)
	}

	wg.Wait()

	expectedSize := goroutines * entriesPerGoroutine
	assert.Equal(t, expectedSize, set.Size(), "All concurrent additions should succeed")
}

func TestLWWSet_ConcurrentMerge(t *testing.T) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	// Заполняем sets
	for i := 0; i < 100; i++ {
		set1.Add(createTestEntry(string(rune(i)), "user1", "node1", int64(i), false))
		set2.Add(createTestEntry(string(rune(i+100)), "user1", "node2", int64(i+100), false))
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Одновременный merge в разные стороны
	go func() {
		defer wg.Done()
		set1.Merge(set2)
	}()

	go func() {
		defer wg.Done()
		set2.Merge(set1)
	}()

	wg.Wait()

	// Оба set должны содержать все элементы
	assert.Equal(t, 200, set1.Size())
	assert.Equal(t, 200, set2.Size())
}

// Benchmark тесты
func BenchmarkLWWSet_Add(b *testing.B) {
	set := NewLWWSet()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := createTestEntry(string(rune(i)), "user1", "node1", int64(i), false)
		set.Add(entry)
	}
}

func BenchmarkLWWSet_Get(b *testing.B) {
	set := NewLWWSet()
	for i := 0; i < 1000; i++ {
		entry := createTestEntry(string(rune(i)), "user1", "node1", int64(i), false)
		set.Add(entry)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		set.Get(string(rune(i % 1000)))
	}
}

func BenchmarkLWWSet_Merge(b *testing.B) {
	set1 := NewLWWSet()
	set2 := NewLWWSet()

	for i := 0; i < 1000; i++ {
		set1.Add(createTestEntry(string(rune(i)), "user1", "node1", int64(i), false))
		set2.Add(createTestEntry(string(rune(i+500)), "user1", "node2", int64(i+500), false))
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		set1.Merge(set2)
	}
}

func TestLWWSet_Update(t *testing.T) {
	set := NewLWWSet()

	entry := createTestEntry("id1", "user1", "node1", 10, false)

	// Вызываем Update (что по сути вызывает Add)
	added := set.Update(entry)
	assert.True(t, added, "Первое добавление должно вернуть true")

	// Добавляем более новую версию через Update
	entryNew := createTestEntry("id1", "user1", "node1", 20, false)
	entryNew.Data = []byte("updated data")
	updated := set.Update(entryNew)
	assert.True(t, updated, "Обновление с новым timestamp должно вернуть true")

	// Добавляем старую версию через Update
	entryOld := createTestEntry("id1", "user1", "node1", 5, false)
	entryOld.Data = []byte("old data")
	updated = set.Update(entryOld)
	assert.False(t, updated, "Обновление со старым timestamp должно вернуть false")
}
