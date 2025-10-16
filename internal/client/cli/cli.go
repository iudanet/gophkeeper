package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/sync"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/validation"
	"golang.org/x/term"
)

type Passwors struct {
	FromFile string
	FromArgs string
}

type Cli struct {
	apiClient     *api.Client
	authService   *auth.AuthService
	dataService   *data.Service
	syncService   *sync.Service
	authData      *storage.AuthData
	encryptionKey []byte
}

func New(apiClient *api.Client, authService *auth.AuthService, dataService *data.Service, syncService *sync.Service) *Cli {
	return &Cli{
		apiClient:   apiClient,
		authService: authService,
		dataService: dataService,
		syncService: syncService,
	}
}

// ReadMasterPassword reads master password from various sources with priority:
// 1. Environment variable GOPHKEEPER_MASTER_PASSWORD
// 2. File specified in masterPasswordFile parameter
// 3. Command-line parameter masterPassword
// 4. Interactive prompt (fallback)
func (c *Cli) ReadMasterPassword(ctx context.Context, passwords Passwors) error {
	// Получаем зашифрованные auth данные для получения username и public salt
	encryptedAuthData, err := c.authService.GetAuthEncryptData(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Получаем master password из различных источников
	password, err := c.getMasterPassword(passwords)
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}

	if err := validation.ValidatePassword(password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	// Деривируем ключи из master password + username + public salt
	keys, err := crypto.DeriveKeysFromBase64Salt(password, encryptedAuthData.Username, encryptedAuthData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// Сохраняем encryption key в памяти для текущей сессии
	c.encryptionKey = keys.EncryptionKey

	// Устанавливаем ключ шифрования в authService
	c.authService.SetEncryptionKey(c.encryptionKey)

	// Получаем расшифрованные auth данные
	authData, err := c.authService.GetAuthDecryptData(ctx)
	if err != nil {
		return fmt.Errorf("failed to decrypt auth data: %w", err)
	}
	c.authData = authData

	// dataService уже создан в конструкторе, encryption key и nodeID передаются в методы
	return nil
}

// getMasterPassword retrieves master password from various sources with priority:
// 1. Environment variable GOPHKEEPER_MASTER_PASSWORD
// 2. File specified in masterPasswordFile parameter
// 3. Command-line parameter masterPassword
// 4. Interactive prompt (fallback)
func (c *Cli) getMasterPassword(passwords Passwors) (string, error) {
	// Priority 1: Environment variable
	if envPassword := os.Getenv("GOPHKEEPER_MASTER_PASSWORD"); envPassword != "" {
		return envPassword, nil
	}

	// Priority 2: File
	if passwords.FromFile != "" {
		content, err := os.ReadFile(passwords.FromFile)
		if err != nil {
			return "", fmt.Errorf("failed to read password file: %w", err)
		}
		// Убираем trailing newline/whitespace
		password := strings.TrimSpace(string(content))
		if password == "" {
			return "", fmt.Errorf("password file is empty")
		}
		return password, nil
	}

	// Priority 3: CLI parameter
	if passwords.FromArgs != "" {
		return passwords.FromArgs, nil
	}

	// Priority 4: Interactive prompt (fallback)
	password, err := readPassword("Master password: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password from stdin: %w", err)
	}
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

func PrintUsage() {
	fmt.Println("GophKeeper Client")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gophkeeper [OPTIONS] COMMAND")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --version                    Show version information")
	fmt.Println("  --server URL                 Server URL (default: http://localhost:8080)")
	fmt.Println("  --db PATH                    Path to local database (default: gophkeeper-client.db)")
	fmt.Println("  --master-password PASSWORD   Master password (not recommended, use env var or file)")
	fmt.Println("  --master-password-file PATH  Path to file containing master password")
	fmt.Println()
	fmt.Println("Master Password Priority (highest to lowest):")
	fmt.Println("  1. GOPHKEEPER_MASTER_PASSWORD environment variable")
	fmt.Println("  2. --master-password-file (file path)")
	fmt.Println("  3. --master-password (command line)")
	fmt.Println("  4. Interactive prompt (fallback)")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  register                Register new user")
	fmt.Println("  login                   Login to server")
	fmt.Println("  logout                  Logout from server")
	fmt.Println("  status                  Show authentication status")
	fmt.Println("  add <type>              Add new data (credential, text, binary, card)")
	fmt.Println("  list <type>             List saved data (credentials, text, binary, cards)")
	fmt.Println("  get <id>                Show full data details")
	fmt.Println("  delete <id>             Delete data (soft delete)")
	fmt.Println("  sync                    Synchronize local data with server")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Interactive password prompt")
	fmt.Println("  gophkeeper register")
	fmt.Println("  gophkeeper login")
	fmt.Println("  gophkeeper list credentials")
	fmt.Println()
	fmt.Println("  # Using environment variable (recommended)")
	fmt.Println("  export GOPHKEEPER_MASTER_PASSWORD='mySecretPassword123'")
	fmt.Println("  gophkeeper sync")
	fmt.Println()
	fmt.Println("  # Using password file (for automation)")
	fmt.Println("  echo 'mySecretPassword123' > ~/.gophkeeper-password")
	fmt.Println("  chmod 600 ~/.gophkeeper-password")
	fmt.Println("  gophkeeper --master-password-file ~/.gophkeeper-password sync")
	fmt.Println()
	fmt.Println("  # Using command line parameter (not recommended)")
	fmt.Println("  gophkeeper --master-password 'mySecretPassword123' add credential")
	fmt.Println()
	fmt.Println("  # Other examples")
	fmt.Println("  gophkeeper add text")
	fmt.Println("  gophkeeper add binary")
	fmt.Println("  gophkeeper add card")
	fmt.Println("  gophkeeper get b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5")
	fmt.Println("  gophkeeper delete b692f5c0-2d88-4aa1-a9e1-13aa6e4976d5")
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
