package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/iocli"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCli_runSync_Success проверяет успешное выполнение синхронизации и вывод отчёта
func TestCli_runSync_Success(t *testing.T) {
	ctx := context.Background()

	mockAuthService := &auth.ServiceMock{
		EnsureTokenValidFunc: func(ctx context.Context) error {
			return nil
		},
		GetAuthDecryptDataFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return &storage.AuthData{
				UserID:      "user-123",
				AccessToken: "valid-access-token",
			}, nil
		},
	}

	mockSyncService := &sync.ServiceMock{
		SyncFunc: func(ctx context.Context, userID string, accessToken string) (*sync.SyncResult, error) {
			return &sync.SyncResult{
				PushedEntries:  2,
				PulledEntries:  3,
				MergedEntries:  3,
				Conflicts:      1,
				SkippedEntries: 0,
			}, nil
		},
	}

	outputLines := []string{}
	var writeBuffer []byte
	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {
			outputLines = append(outputLines, joinArgs(a))
		},
		PrintfFunc: func(format string, a ...any) {
			outputLines = append(outputLines, fmt.Sprintf(format, a...))
		},
		WriteFunc: func(p []byte) (int, error) {
			writeBuffer = append(writeBuffer, p...)
			return len(p), nil
		},
	}
	cli := &Cli{
		io:          mockIO,
		authService: mockAuthService,
		syncService: mockSyncService,
		authData: &storage.AuthData{
			UserID:      "user-123",
			AccessToken: "valid-access-token",
		},
		encryptionKey: []byte("01234567890123456789012345678901"), // 32 байта
	}

	err := cli.runSync(ctx)

	require.NoError(t, err, "runSync should not return error")

	// Проверяем, что методы вызвались
	assert.Len(t, mockAuthService.EnsureTokenValidCalls(), 1)
	assert.Len(t, mockAuthService.GetAuthDecryptDataCalls(), 1)
	assert.Len(t, mockSyncService.SyncCalls(), 1)

	output := strings.Join(outputLines, "\n") + string(writeBuffer)

	assert.Contains(t, output, "Starting synchronization with server...")
	assert.Contains(t, output, "Synchronization completed successfully")
	assert.Contains(t, output, "Pushed to server:   2 entries")
	assert.Contains(t, output, "Pulled from server: 3 entries")
	assert.Contains(t, output, "Merged locally:     3 entries")
	assert.Contains(t, output, "Conflicts resolved: 1")
}

// TestCli_runSync_EnsureTokenValidFails проверяет ошибку если EnsureTokenValid возвращает ошибку
func TestCli_runSync_EnsureTokenValidFails(t *testing.T) {
	ctx := context.Background()

	mockAuthService := &auth.ServiceMock{
		EnsureTokenValidFunc: func(ctx context.Context) error {
			return errors.New("token invalid")
		},
	}
	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		WriteFunc:   func(p []byte) (int, error) { return len(p), nil },
	}
	cli := &Cli{
		io:          mockIO,
		authService: mockAuthService,
		authData: &storage.AuthData{
			UserID:      "user-123",
			AccessToken: "some-access-token",
		},
		encryptionKey: []byte("dummy-encryption-key-0123456789012345"), // 32 байта или больше
	}

	err := cli.runSync(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "token invalid")
}

// TestCli_runSync_SyncFails проверяет ошибку если sync.Service.Sync возвращает ошибку
func TestCli_runSync_SyncFails(t *testing.T) {
	ctx := context.Background()

	mockAuthService := &auth.ServiceMock{
		EnsureTokenValidFunc: func(ctx context.Context) error {
			return nil
		},
		GetAuthDecryptDataFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return &storage.AuthData{
				UserID:      "user-123",
				AccessToken: "token",
			}, nil
		},
	}

	mockSyncService := &sync.ServiceMock{
		SyncFunc: func(ctx context.Context, userID string, accessToken string) (*sync.SyncResult, error) {
			return nil, errors.New("sync failed")
		},
	}
	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		WriteFunc:   func(p []byte) (int, error) { return len(p), nil },
	}

	cli := &Cli{
		io:          mockIO,
		authService: mockAuthService,
		syncService: mockSyncService,
		authData: &storage.AuthData{
			UserID:      "user-123",
			AccessToken: "token",
		},
		encryptionKey: []byte("dummy-encryption-key-0123456789012345"),
	}

	err := cli.runSync(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "sync failed")
}

// TestCli_runSync_GetAuthDecryptDataFails проверяет ошибку если GetAuthDecryptData возвращает ошибку
func TestCli_runSync_GetAuthDecryptDataFails(t *testing.T) {
	ctx := context.Background()
	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		WriteFunc:   func(p []byte) (int, error) { return len(p), nil },
	}
	mockAuthService := &auth.ServiceMock{
		EnsureTokenValidFunc: func(ctx context.Context) error {
			return nil
		},
		GetAuthDecryptDataFunc: func(ctx context.Context) (*storage.AuthData, error) {
			return nil, errors.New("failed to decrypt auth")
		},
	}

	cli := &Cli{
		io:          mockIO,
		authService: mockAuthService,
		authData: &storage.AuthData{
			UserID:      "user-123",
			AccessToken: "token",
		},
		encryptionKey: []byte("dummy-encryption-key-0123456789012345"),
	}

	err := cli.runSync(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt auth")
}

// joinArgs объединяет аргументы в строку с пробелами (упрощённый Println)
func joinArgs(args []any) string {
	str := ""
	for i, a := range args {
		if i > 0 {
			str += " "
		}
		str += fmt.Sprintf("%v", a)
	}
	return str
}
