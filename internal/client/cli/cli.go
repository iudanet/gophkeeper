package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"golang.org/x/term"
)

type Cli struct {
	apiClient   *api.Client
	boltStorage *boltdb.Storage
	keys        *crypto.Keys
	authData    *storage.AuthData
}

func New(apiClient *api.Client, boltStorage *boltdb.Storage) *Cli {
	return &Cli{
		apiClient:   apiClient,
		boltStorage: boltStorage,
	}
}

func (c *Cli) ReadMasterMasspwrd(ctx context.Context) error {
	// Проверяем авторизацию
	authData, err := c.boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}
	c.authData = authData

	// Запрашиваем master password для получения encryption_key
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Деривируем ключи
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, c.authData.Username, c.authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}
	c.keys = keys
	return nil
}

func PrintUsage() {
	fmt.Println("GophKeeper Client")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gophkeeper [OPTIONS] COMMAND")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --version          Show version information")
	fmt.Println("  --server URL       Server URL (default: http://localhost:8080)")
	fmt.Println("  --db PATH          Path to local database (default: gophkeeper-client.db)")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  register           Register new user")
	fmt.Println("  login              Login to server")
	fmt.Println("  logout             Logout from server")
	fmt.Println("  status             Show authentication status")
	fmt.Println("  add credential     Add new credential (login/password)")
	fmt.Println("  list credentials   List all saved credentials")
	fmt.Println("  get <id>           Show full credential details including password")
	fmt.Println("  delete <id>        Delete credential (soft delete)")
	fmt.Println("  sync               Synchronize local data with server")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  gophkeeper register")
	fmt.Println("  gophkeeper login")
	fmt.Println("  gophkeeper logout")
	fmt.Println("  gophkeeper add credential")
	fmt.Println("  gophkeeper list credentials")
	fmt.Println("  gophkeeper get b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5")
	fmt.Println("  gophkeeper delete b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5")
	fmt.Println("  gophkeeper sync")
	fmt.Println("  gophkeeper --server https://example.com login")
}

// readInput читает строку из stdin
func readInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// readPassword читает пароль без отображения на экране
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Переход на новую строку после ввода пароля
	if err != nil {
		return "", err
	}
	return string(passwordBytes), nil
}
