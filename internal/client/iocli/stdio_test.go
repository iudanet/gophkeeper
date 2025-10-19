package iocli

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Проверяем что NewStdio возвращает валидный объект
func TestNewStdio(t *testing.T) {
	stdio := NewStdio()
	assert.NotNil(t, stdio)
}

// Тесты для Println и Printf — переадресуют в fmt.Println/Printf,
// здесь можно проверить просто, что вызовы не падают.
func TestPrintlnAndPrintf(t *testing.T) {
	stdio := NewStdio()

	// Здесь мы на самом деле ничего не захватываем,
	// но проверяем, что методы вызываются без panic
	assert.NotPanics(t, func() {
		stdio.Println("hello", "world")
	})
	assert.NotPanics(t, func() {
		stdio.Printf("test %d %s", 1, "abc")
	})
}

// Тест ReadInput: читаем из буфера вместо os.Stdin
func TestReadInput(t *testing.T) {
	// Подменяем os.Stdin на входящий буфер
	input := "user input\n"
	r, w, err := os.Pipe()
	assert.NoError(t, err)

	// Пишем в pipe в отдельной горутине, имитируя ввод пользователя
	go func() {
		_, _ = w.Write([]byte(input))
		_ = w.Close()
	}()

	// Сохраняем старый os.Stdin и восстанавливаем после
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	stdio := NewStdio()
	result, err := stdio.ReadInput("Prompt: ")
	assert.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(input), result)
}
