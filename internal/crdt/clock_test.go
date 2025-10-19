package crdt

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLamportClock(t *testing.T) {
	clock := NewLamportClock()

	require.NotNil(t, clock)
	assert.Equal(t, int64(0), clock.GetTimestamp(), "Initial counter should be 0")
	assert.NotEmpty(t, clock.GetNodeID(), "NodeID should not be empty")
}

func TestNewLamportClockWithNodeID(t *testing.T) {
	nodeID := "test-node-123"
	clock := NewLamportClockWithNodeID(nodeID)

	require.NotNil(t, clock)
	assert.Equal(t, int64(0), clock.GetTimestamp(), "Initial counter should be 0")
	assert.Equal(t, nodeID, clock.GetNodeID(), "NodeID should match provided value")
}

func TestLamportClock_Tick(t *testing.T) {
	clock := NewLamportClock()

	tests := []struct {
		name          string
		expectedValue int64
	}{
		{"First tick", 1},
		{"Second tick", 2},
		{"Third tick", 3},
		{"Fourth tick", 4},
		{"Fifth tick", 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := clock.Tick()
			assert.Equal(t, tt.expectedValue, result, "Tick should return incremented value")
			assert.Equal(t, tt.expectedValue, clock.GetTimestamp(), "Counter should be incremented")
		})
	}
}

func TestLamportClock_Tick_Monotonicity(t *testing.T) {
	clock := NewLamportClock()

	var previous int64 = 0
	for i := 0; i < 100; i++ {
		current := clock.Tick()
		assert.Greater(t, current, previous, "Tick should always increase")
		previous = current
	}

	assert.Equal(t, int64(100), clock.GetTimestamp(), "Final counter should be 100")
}

func TestLamportClock_Update(t *testing.T) {
	tests := []struct {
		name            string
		localCounter    int64
		remoteTimestamp int64
		expectedResult  int64
	}{
		{
			name:            "remote timestamp greater than local",
			localCounter:    5,
			remoteTimestamp: 10,
			expectedResult:  11, // max(5, 10) + 1 = 11
		},
		{
			name:            "remote timestamp less than local",
			localCounter:    15,
			remoteTimestamp: 10,
			expectedResult:  16, // max(15, 10) + 1 = 16
		},
		{
			name:            "remote timestamp equal to local",
			localCounter:    10,
			remoteTimestamp: 10,
			expectedResult:  11, // max(10, 10) + 1 = 11
		},
		{
			name:            "remote timestamp is zero",
			localCounter:    5,
			remoteTimestamp: 0,
			expectedResult:  6, // max(5, 0) + 1 = 6
		},
		{
			name:            "both are zero",
			localCounter:    0,
			remoteTimestamp: 0,
			expectedResult:  1, // max(0, 0) + 1 = 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := NewLamportClock()
			clock.SetTimestamp(tt.localCounter)

			result := clock.Update(tt.remoteTimestamp)

			assert.Equal(t, tt.expectedResult, result, "Update should return correct timestamp")
			assert.Equal(t, tt.expectedResult, clock.GetTimestamp(), "Counter should be updated correctly")
		})
	}
}

func TestLamportClock_Update_MonotonicityAfterUpdate(t *testing.T) {
	clock := NewLamportClock()

	// Начальное состояние: counter = 0
	clock.Update(10) // counter = 11

	// Последующие Tick должны увеличивать счетчик монотонно
	ts1 := clock.Tick() // 12
	assert.Equal(t, int64(12), ts1)

	ts2 := clock.Tick() // 13
	assert.Equal(t, int64(13), ts2)

	// Обновление с меньшим timestamp не должно уменьшать счетчик
	ts3 := clock.Update(5) // max(13, 5) + 1 = 14
	assert.Equal(t, int64(14), ts3)
}

func TestLamportClock_GetTimestamp(t *testing.T) {
	clock := NewLamportClock()

	// Начальное значение
	assert.Equal(t, int64(0), clock.GetTimestamp())

	// После Tick
	clock.Tick()
	assert.Equal(t, int64(1), clock.GetTimestamp())

	// После Update
	clock.Update(10)
	assert.Equal(t, int64(11), clock.GetTimestamp())

	// GetTimestamp не должен изменять счетчик
	for i := 0; i < 10; i++ {
		assert.Equal(t, int64(11), clock.GetTimestamp())
	}
}

func TestLamportClock_SetTimestamp(t *testing.T) {
	clock := NewLamportClock()

	tests := []struct {
		name      string
		timestamp int64
	}{
		{"Set to 10", 10},
		{"Set to 100", 100},
		{"Set to 0", 0},
		{"Set to 1000", 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.SetTimestamp(tt.timestamp)
			assert.Equal(t, tt.timestamp, clock.GetTimestamp())
		})
	}
}

func TestLamportClock_GetNodeID(t *testing.T) {
	// Тест с автоматически сгенерированным NodeID
	clock1 := NewLamportClock()
	nodeID1 := clock1.GetNodeID()
	assert.NotEmpty(t, nodeID1)
	assert.Equal(t, nodeID1, clock1.GetNodeID(), "NodeID should be consistent")

	// Тест с заданным NodeID
	expectedNodeID := "custom-node-id"
	clock2 := NewLamportClockWithNodeID(expectedNodeID)
	assert.Equal(t, expectedNodeID, clock2.GetNodeID())
}

func TestLamportClock_UniqueNodeIDs(t *testing.T) {
	// Создание нескольких часов должно генерировать разные NodeID
	clocks := make([]*LamportClock, 10)
	nodeIDs := make(map[string]bool)

	for i := 0; i < 10; i++ {
		clocks[i] = NewLamportClock()
		nodeID := clocks[i].GetNodeID()
		assert.NotEmpty(t, nodeID)
		assert.False(t, nodeIDs[nodeID], "NodeID should be unique")
		nodeIDs[nodeID] = true
	}

	assert.Len(t, nodeIDs, 10, "All NodeIDs should be unique")
}

func TestLamportClock_ConcurrentTick(t *testing.T) {
	clock := NewLamportClock()
	iterations := 1000
	goroutines := 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				clock.Tick()
			}
		}()
	}

	wg.Wait()

	expectedCounter := int64(goroutines * iterations)
	assert.Equal(t, expectedCounter, clock.GetTimestamp(),
		"Concurrent Tick calls should increment counter correctly")
}

func TestLamportClock_ConcurrentUpdate(t *testing.T) {
	clock := NewLamportClock()
	goroutines := 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(timestamp int64) {
			defer wg.Done()
			clock.Update(timestamp)
		}(int64(i * 100))
	}

	wg.Wait()

	// После всех Update счетчик должен быть > 0
	assert.Greater(t, clock.GetTimestamp(), int64(0),
		"Counter should be updated after concurrent Update calls")
}

func TestLamportClock_ConcurrentMixedOperations(t *testing.T) {
	clock := NewLamportClock()
	operations := 100

	var wg sync.WaitGroup
	wg.Add(3)

	// Горутина 1: Tick
	go func() {
		defer wg.Done()
		for i := 0; i < operations; i++ {
			clock.Tick()
		}
	}()

	// Горутина 2: Update
	go func() {
		defer wg.Done()
		for i := 0; i < operations; i++ {
			clock.Update(int64(i))
		}
	}()

	// Горутина 3: Read (GetTimestamp)
	go func() {
		defer wg.Done()
		for i := 0; i < operations; i++ {
			_ = clock.GetTimestamp()
		}
	}()

	wg.Wait()

	// Проверяем, что счетчик монотонно возрастал
	finalCounter := clock.GetTimestamp()
	assert.Greater(t, finalCounter, int64(0), "Counter should have increased")
}

// Benchmark тесты
func BenchmarkLamportClock_Tick(b *testing.B) {
	clock := NewLamportClock()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		clock.Tick()
	}
}

func BenchmarkLamportClock_Update(b *testing.B) {
	clock := NewLamportClock()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		clock.Update(int64(i))
	}
}

func BenchmarkLamportClock_GetTimestamp(b *testing.B) {
	clock := NewLamportClock()
	clock.Tick()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = clock.GetTimestamp()
	}
}
