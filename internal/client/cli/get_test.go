package cli

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/iocli"
	"github.com/iudanet/gophkeeper/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCli_runGet_Credential(t *testing.T) {
	ctx := context.Background()

	cred := &models.Credential{
		ID:       "cred1",
		Name:     "GitHub",
		Login:    "user1",
		Password: "pass123",
		URL:      "https://github.com",
		Notes:    "some notes",
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return "", nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			if id == cred.ID {
				return cred, nil
			}
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{cred.ID})
	require.NoError(t, err)
}

func TestCli_runGet_TextData(t *testing.T) {
	ctx := context.Background()

	text := &models.TextData{
		ID:      "text1",
		Name:    "Note 1",
		Content: "This is a secret note.",
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return "", nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			if id == text.ID {
				return text, nil
			}
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{text.ID})
	require.NoError(t, err)
}

func TestCli_runGet_BinaryData_SaveSkipped(t *testing.T) {
	ctx := context.Background()

	binary := &models.BinaryData{
		ID:       "bin1",
		Name:     "file.txt",
		MimeType: "text/plain",
		Data:     []byte("file content"),
		Metadata: models.Metadata{
			CustomFields: map[string]string{
				"filename": "file.txt",
			},
		},
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return "", nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			if id == binary.ID {
				return binary, nil
			}
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{binary.ID})
	require.NoError(t, err)
}

func TestCli_runGet_BinaryData_SaveFile(t *testing.T) {
	ctx := context.Background()

	binary := &models.BinaryData{
		ID:       "bin1",
		Name:     "file.txt",
		MimeType: "text/plain",
		Data:     []byte("file content"),
		Metadata: models.Metadata{
			CustomFields: map[string]string{
				"filename": "file.txt",
			},
		},
	}

	tmpFile := "test_output.bin"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return tmpFile, nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			if id == binary.ID {
				return binary, nil
			}
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{binary.ID})
	require.NoError(t, err)

	info, err := os.Stat(tmpFile)
	require.NoError(t, err)
	assert.Equal(t, int64(len(binary.Data)), info.Size())
}

func TestCli_runGet_CardData(t *testing.T) {
	ctx := context.Background()

	card := &models.CardData{
		ID:     "card1",
		Name:   "Visa Gold",
		Number: "4111111111111111",
		Holder: "John Doe",
		Expiry: "12/25",
		CVV:    "123",
		PIN:    "9999",
	}

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return "", nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			if id == card.ID {
				return card, nil
			}
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{card.ID})
	require.NoError(t, err)
}

func TestCli_runGet_EntryNotFound(t *testing.T) {
	ctx := context.Background()

	mockIO := &iocli.IOMock{
		PrintlnFunc: func(a ...any) {},
		PrintfFunc:  func(format string, a ...any) {},
		ReadInputFunc: func(prompt string) (string, error) {
			return "", nil
		},
		WriteFunc: func(p []byte) (int, error) {
			return len(p), nil
		},
	}
	mockData := &data.ServiceMock{
		GetCredentialFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.Credential, error) {
			return nil, errors.New("not found")
		},
		GetTextDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.TextData, error) {
			return nil, errors.New("not found")
		},
		GetBinaryDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.BinaryData, error) {
			return nil, errors.New("not found")
		},
		GetCardDataFunc: func(ctx context.Context, id string, encryptionKey []byte) (*models.CardData, error) {
			return nil, errors.New("not found")
		},
	}

	cli := &Cli{
		io:            mockIO,
		dataService:   mockData,
		encryptionKey: []byte("dummy"),
	}

	err := cli.runGet(ctx, []string{"nonexistent-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entry not found")
}

func TestCli_runGet_MissingID(t *testing.T) {
	ctx := context.Background()

	cli := &Cli{}

	err := cli.runGet(ctx, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing entry ID")
}
