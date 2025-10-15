package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/crypto"
	"github.com/iudanet/gophkeeper/internal/models"
)

var (
	// Version information set via ldflags during build
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Глобальные флаги
	showVersion := flag.Bool("version", false, "Show version information")
	serverURL := flag.String("server", "http://localhost:8080", "Server URL")
	dbPath := flag.String("db", "gophkeeper-client.db", "Path to local database")

	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Получаем команду
	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	command := args[0]

	// Создаем контекст
	ctx := context.Background()

	// Открываем BoltDB storage
	boltStorage, err := boltdb.New(ctx, *dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := boltStorage.Close(); err != nil {
			slog.Error("failed to close database", "error", err)
		}
	}()

	// Создаем API клиент
	apiClient := api.NewClient(*serverURL)

	// Выполняем команду
	switch command {
	case "register":
		if err := runRegister(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if err := runLogin(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "logout":
		if err := runLogout(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := runStatus(ctx, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "add":
		if err := runAdd(ctx, args[1:], boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("GophKeeper Client\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
}

func printUsage() {
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
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  gophkeeper register")
	fmt.Println("  gophkeeper login")
	fmt.Println("  gophkeeper logout")
	fmt.Println("  gophkeeper add credential")
	fmt.Println("  gophkeeper --server https://example.com login")
}

func runRegister(ctx context.Context, apiClient *api.Client, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Registration ===")
	fmt.Println()

	// Запрашиваем username
	username, err := readInput("Username: ")
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Запрашиваем master password
	masterPassword, err := readPassword("Master password (min 12 chars): ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Подтверждение пароля
	confirmPassword, err := readPassword("Confirm master password: ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if masterPassword != confirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	fmt.Println()
	fmt.Println("Registering user...")

	// Создаем auth.Service (без authStore, т.к. еще нет encryption_key)
	authService := auth.NewService(apiClient, nil)

	// Регистрация
	result, err := authService.Register(ctx, username, masterPassword)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ Registration successful!")
	fmt.Printf("User ID: %s\n", result.UserID)
	fmt.Printf("Username: %s\n", result.Username)
	fmt.Println()
	fmt.Println("⚠️  IMPORTANT: Remember your master password!")
	fmt.Println("   If you lose it, you will NOT be able to recover your data.")
	fmt.Println()
	fmt.Println("Please run 'gophkeeper login' to start using the service.")

	return nil
}

func runLogin(ctx context.Context, apiClient *api.Client, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Login ===")
	fmt.Println()

	// Запрашиваем username
	username, err := readInput("Username: ")
	if err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Запрашиваем master password
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	fmt.Println()
	fmt.Println("Authenticating...")

	// Создаем auth.Service (без authStore на этом этапе)
	authService := auth.NewService(apiClient, nil)

	// Логин
	result, err := authService.Login(ctx, username, masterPassword)
	if err != nil {
		return err
	}

	// Теперь у нас есть encryption_key, создаем AuthService (слой шифрования)
	authStore := auth.NewAuthService(boltStorage, result.EncryptionKey)

	// Сохраняем токены через слой шифрования
	authData := &storage.AuthData{
		Username:     result.Username,
		AccessToken:  result.AccessToken,  // plaintext
		RefreshToken: result.RefreshToken, // plaintext
		PublicSalt:   result.PublicSalt,
		ExpiresAt:    time.Now().Unix() + result.ExpiresIn,
	}

	if err := authStore.SaveAuth(ctx, authData); err != nil {
		return fmt.Errorf("failed to save auth data: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Login successful!")
	fmt.Printf("Username: %s\n", result.Username)
	fmt.Printf("Access token expires in: %d seconds\n", result.ExpiresIn)
	fmt.Println()
	fmt.Println("Your session has been saved securely.")

	return nil
}

func runLogout(ctx context.Context, apiClient *api.Client, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Logout ===")
	fmt.Println()

	// Проверяем, есть ли сохраненная сессия
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			fmt.Println("No active session found.")
			return nil
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Нужен encryption_key для расшифровки токена
	// Запрашиваем master password
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Деривируем ключи
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	// Создаем authStore с encryption_key
	authStore := auth.NewAuthService(boltStorage, keys.EncryptionKey)

	// Создаем auth.Service с authStore
	authService := auth.NewService(apiClient, authStore)

	// Выполняем logout
	if err := authService.Logout(ctx); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}

	fmt.Println("✓ Logout successful!")
	fmt.Println("Your local session has been deleted.")

	return nil
}

func runStatus(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Authentication Status ===")
	fmt.Println()

	// Проверяем наличие сохраненной сессии
	isAuth, err := boltStorage.IsAuthenticated(ctx)
	if err != nil {
		return fmt.Errorf("failed to check authentication: %w", err)
	}

	if !isAuth {
		fmt.Println("Status: Not authenticated")
		fmt.Println()
		fmt.Println("Run 'gophkeeper login' to authenticate.")
		return nil
	}

	// Получаем данные
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	expiresAt := time.Unix(authData.ExpiresAt, 0)
	remaining := time.Until(expiresAt)

	fmt.Println("Status: Authenticated")
	fmt.Printf("Username: %s\n", authData.Username)
	fmt.Printf("Token expires: %s\n", expiresAt.Format(time.RFC3339))

	if remaining > 0 {
		fmt.Printf("Time remaining: %s\n", remaining.Round(time.Second))
	} else {
		fmt.Println("⚠️  Token has expired. Please login again.")
	}

	return nil
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

func runAdd(ctx context.Context, args []string, boltStorage *boltdb.Storage) error {
	// Проверяем подкоманду
	if len(args) == 0 {
		return fmt.Errorf("missing data type. Usage: gophkeeper add <credential|text|binary|card>")
	}

	dataType := args[0]

	switch dataType {
	case "credential":
		return runAddCredential(ctx, boltStorage)
	case "text":
		return fmt.Errorf("'add text' not implemented yet")
	case "binary":
		return fmt.Errorf("'add binary' not implemented yet")
	case "card":
		return fmt.Errorf("'add card' not implemented yet")
	default:
		return fmt.Errorf("unknown data type: %s. Use: credential, text, binary, or card", dataType)
	}
}

func runAddCredential(ctx context.Context, boltStorage *boltdb.Storage) error {
	fmt.Println("=== Add Credential ===")
	fmt.Println()

	// Проверяем авторизацию
	authData, err := boltStorage.GetAuth(ctx)
	if err != nil {
		if err == storage.ErrAuthNotFound {
			return fmt.Errorf("not authenticated. Please run 'gophkeeper login' first")
		}
		return fmt.Errorf("failed to get auth data: %w", err)
	}

	// Запрашиваем master password для получения encryption_key
	masterPassword, err := readPassword("Master password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Деривируем ключи
	keys, err := crypto.DeriveKeysFromBase64Salt(masterPassword, authData.Username, authData.PublicSalt)
	if err != nil {
		return fmt.Errorf("failed to derive keys: %w", err)
	}

	fmt.Println()
	fmt.Println("Enter credential details:")
	fmt.Println()

	// Запрашиваем данные credentials
	name, err := readInput("Name (e.g., 'GitHub', 'Gmail'): ")
	if err != nil {
		return fmt.Errorf("failed to read name: %w", err)
	}
	if name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	login, err := readInput("Login/Email: ")
	if err != nil {
		return fmt.Errorf("failed to read login: %w", err)
	}
	if login == "" {
		return fmt.Errorf("login cannot be empty")
	}

	password, err := readPassword("Password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	url, err := readInput("URL (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read URL: %w", err)
	}

	notes, err := readInput("Notes (optional): ")
	if err != nil {
		return fmt.Errorf("failed to read notes: %w", err)
	}

	// Создаем credential
	cred := &models.Credential{
		Name:     name,
		Login:    login,
		Password: password,
		URL:      url,
		Notes:    notes,
		Metadata: models.Metadata{
			Favorite: false,
			Tags:     []string{},
		},
	}

	// Получаем User ID из authData
	// Примечание: в текущей реализации userID хранится в authData (возможно потребуется добавить)
	// Для простоты используем username как userID
	userID := authData.Username

	// Генерируем nodeID (уникальный ID клиента)
	// В реальном приложении это должен быть постоянный ID, сохраненный в БД
	nodeID := fmt.Sprintf("%s-client", authData.Username)

	// Создаем data service
	dataService := data.NewService(boltStorage, keys.EncryptionKey, nodeID)

	// Добавляем credential
	if err := dataService.AddCredential(ctx, userID, cred); err != nil {
		return fmt.Errorf("failed to add credential: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Credential added successfully!")
	fmt.Printf("Name: %s\n", name)
	fmt.Printf("Login: %s\n", login)
	fmt.Println()
	fmt.Println("Note: Credential is stored locally. Run 'gophkeeper sync' to sync with server (not implemented yet).")

	return nil
}
