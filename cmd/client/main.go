package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
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

	// Создаем API клиент
	apiClient := api.NewClient(*serverURL)
	authService := auth.NewService(apiClient)

	// Выполняем команду
	ctx := context.Background()

	switch command {
	case "register":
		if err := runRegister(ctx, authService); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if err := runLogin(ctx, authService); err != nil {
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
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  register           Register new user")
	fmt.Println("  login              Login to server")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  gophkeeper register")
	fmt.Println("  gophkeeper login")
	fmt.Println("  gophkeeper --server https://example.com login")
}

func runRegister(ctx context.Context, authService *auth.Service) error {
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

	return nil
}

func runLogin(ctx context.Context, authService *auth.Service) error {
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

	// Логин
	result, err := authService.Login(ctx, username, masterPassword)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("✓ Login successful!")
	fmt.Printf("Username: %s\n", result.Username)
	fmt.Printf("Access token expires in: %d seconds\n", result.ExpiresIn)
	fmt.Println()
	fmt.Println("Note: Tokens are displayed here for demonstration.")
	fmt.Println("In production, they should be saved securely.")
	fmt.Println()
	fmt.Printf("Access Token:  %s\n", result.AccessToken)
	fmt.Printf("Refresh Token: %s\n", result.RefreshToken)

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
