package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/iocli"
	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCli_runListCredentials_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {
			// Можно логировать, или собирать вызовы в слайс
		},
		PrintfFunc: func(format string, a ...any) {
			// Логируем вызовы или игнорируем для простоты
		},
	}

	mockData := &data.ServiceMock{
		ListCredentialsFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.Credential, error) {
			return []*models.Credential{}, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListCredentials(ctx)
	require.NoError(t, err)

	// Проверим что как минимум вызов Println был с сообщением о пустом списке
	// Т.к. Texts и Printfs не сохраняются, то просто проверим количество вызовов
	printlnCalls := mockIO.PrintlnCalls()
	assert.GreaterOrEqual(t, len(printlnCalls), 3, "Должно быть несколько вызовов Println")

	// Первое сообщение должно содержать "Saved Credentials"
	firstCallArgs := printlnCalls[0].A
	assert.Contains(t, firstCallArgs[0], "Saved Credentials")

	// Проверим что одно из сообщений содержит "No credentials found"
	hasNoCredentialsMsg := false
	for _, call := range printlnCalls {
		for _, arg := range call.A {
			if str, ok := arg.(string); ok && (str == "No credentials found." || containsIgnoreCase(str, "no credentials found")) {
				hasNoCredentialsMsg = true
			}
		}
	}
	assert.True(t, hasNoCredentialsMsg, "Должно быть сообщение о пустом списке")
}

func TestCli_runListCredentials_WithEntries(t *testing.T) {
	ctx := context.Background()

	creds := []*models.Credential{
		{
			ID:    "cred1",
			Name:  "GitHub",
			Login: "user1",
			URL:   "https://github.com",
		},
		{
			ID:    "cred2",
			Name:  "Gmail",
			Login: "user2@example.com",
		},
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {
			// Допустим можно записывать вызовы, если надо
		},
		PrintfFunc: func(format string, a ...any) {
			// Аналогично
		},
	}

	mockData := &data.ServiceMock{
		ListCredentialsFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.Credential, error) {
			return creds, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListCredentials(ctx)
	require.NoError(t, err)

	// Проверим вывод списка - вызовы Printf должны содержать имена и ID
	printfCalls := mockIO.PrintfCalls()
	require.NotEmpty(t, printfCalls)

	var printedNames []string
	var printedIDs []string

	for _, call := range printfCalls {
		if call.Format == "%d. %s\n" && len(call.A) == 2 {
			if name, ok := call.A[1].(string); ok {
				printedNames = append(printedNames, name)
			}
		} else if call.Format == "   ID:    %s\n" && len(call.A) == 1 {
			if id, ok := call.A[0].(string); ok {
				printedIDs = append(printedIDs, id)
			}
		}
	}

	// Проверяем, что имена из creds напечатаны
	foundGitHub := false
	foundGmail := false
	for _, name := range printedNames {
		if name == "GitHub" {
			foundGitHub = true
		}
		if name == "Gmail" {
			foundGmail = true
		}
	}
	assert.True(t, foundGitHub, "Должна быть распечатана запись GitHub")
	assert.True(t, foundGmail, "Должна быть распечатана запись Gmail")

	// Проверяем что IDs напечатаны
	for _, cred := range creds {
		assert.Contains(t, printedIDs, cred.ID)
	}
}

func TestCli_runListCredentials_DataServiceError(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListCredentialsFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.Credential, error) {
			return nil, errors.New("storage failure")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListCredentials(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list credentials")
}

func TestCli_runListText_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListTextDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.TextData, error) {
			return []*models.TextData{}, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListText(ctx)
	require.NoError(t, err)
}

func TestCli_runListText_WithEntries(t *testing.T) {
	ctx := context.Background()

	texts := []*models.TextData{
		{
			ID:      "text1",
			Name:    "Note 1",
			Content: "This is a secret note.",
		},
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListTextDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.TextData, error) {
			return texts, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListText(ctx)
	require.NoError(t, err)
}

func TestCli_runListBinary_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListBinaryDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.BinaryData, error) {
			return []*models.BinaryData{}, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListBinary(ctx)
	require.NoError(t, err)
}

func TestCli_runListBinary_WithEntries(t *testing.T) {
	ctx := context.Background()

	binaries := []*models.BinaryData{
		{
			ID:       "bin1",
			Name:     "file.txt",
			MimeType: "text/plain",
			Data:     []byte("content"),
			Metadata: models.Metadata{
				CustomFields: map[string]string{
					"filename": "file.txt",
				},
			},
		},
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListBinaryDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.BinaryData, error) {
			return binaries, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListBinary(ctx)
	require.NoError(t, err)
}

func TestCli_runListCard_EmptyList(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListCardDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.CardData, error) {
			return []*models.CardData{}, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListCards(ctx)
	require.NoError(t, err)
}

func TestCli_runListCard_WithEntries(t *testing.T) {
	ctx := context.Background()

	cards := []*models.CardData{
		{
			ID:     "card1",
			Name:   "Visa",
			Number: "4111111111111111",
		},
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
	}
	mockData := &data.ServiceMock{
		ListCardDataFunc: func(ctx context.Context, encryptionKey []byte) ([]*models.CardData, error) {
			return cards, nil
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy-key"),
	}

	err := cli.runListCards(ctx)
	require.NoError(t, err)
}

// Вспомогательная функция для поиска подстроки без учета регистра
func containsIgnoreCase(s, substr string) bool {
	s, substr = toLower(s), toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && (s == substr || contains(s[1:], substr)))
}
