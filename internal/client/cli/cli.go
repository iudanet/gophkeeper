package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/iocli"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/sync"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/validation"
)

type Passwords struct {
	FromFile string
	FromArgs string
}

type Cli struct {
	io            iocli.IO
	apiClient     *api.Client
	authService   *auth.AuthService
	dataService   data.Service
	syncService   *sync.Service
	authData      *storage.AuthData
	pass          *Passwords // временно храним. при возможности удаляем
	encryptionKey []byte
}

func New(apiClient *api.Client, authService *auth.AuthService, dataService data.Service, syncService *sync.Service, io iocli.IO, pass *Passwords) *Cli {
	return &Cli{
		io:          io,
		apiClient:   apiClient,
		authService: authService,
		dataService: dataService,
		syncService: syncService,
		pass:        pass,
	}
}

// ReadMasterPassword reads master password from various sources with priority:
// 1. Environment variable GOPHKEEPER_MASTER_PASSWORD
// 2. File specified in masterPasswordFile parameter
// 3. Command-line parameter masterPassword
// 4. Interactive prompt (fallback)
func (c *Cli) ReadMasterPassword(ctx context.Context) error {
	// Получаем зашифрованные auth данные для получения username и public salt
	encryptedAuthData, err := c.authService.GetAuthEncryptData(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Получаем master password из различных источников
	password, err := c.getMasterPassword(*c.pass)
	if err != nil {
		return fmt.Errorf("failed to get master password: %w", err)
	}

	// очищаем пароль после использования
	c.pass = nil

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
func (c *Cli) getMasterPassword(passwords Passwords) (string, error) {
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
	password, err := c.io.ReadPassword("Master password: ")
	if err != nil {
		return "", fmt.Errorf("failed to read password from stdin: %w", err)
	}
	if password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if err := validation.ValidatePassword(password); err != nil {
		return "", fmt.Errorf("invalid password: %w", err)
	}
	return password, nil
}

func (c *Cli) printTemplate(tmplStr string, data interface{}) error {
	tmpl, err := template.New("output").Parse(tmplStr)
	if err != nil {
		return err
	}

	return tmpl.Execute(c.io, data)
}

func PrintUsage() {
	tmpl := template.Must(template.New("usage").Parse(usageTemplate))
	_ = tmpl.Execute(os.Stdout, nil)
}
