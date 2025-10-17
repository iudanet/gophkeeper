package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/auth"
	"github.com/iudanet/gophkeeper/internal/client/cli"
	"github.com/iudanet/gophkeeper/internal/client/data"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
	"github.com/iudanet/gophkeeper/internal/client/sync"
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
	masterPassword := flag.String("master-password", "", "Master password (use with caution, prefer env var or file)")
	masterPasswordFile := flag.String("master-password-file", "", "Path to file containing master password")

	// TLS flags
	tlsCA := flag.String("tls-ca", "", "Path to CA certificate for validating self-signed server certificate")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification (development only)")

	flag.Parse()
	pass := cli.Passwords{
		FromFile: *masterPasswordFile,
		FromArgs: *masterPassword,
	}
	// Show version and exit if requested
	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Получаем команду
	args := flag.Args()
	if len(args) == 0 {
		cli.PrintUsage()
		os.Exit(1)
	}

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

	// Создаем logger
	logger := slog.Default()

	// Создаем API клиент с TLS настройками
	apiClient := api.NewClientWithOptions(api.ClientOptions{
		BaseURL:    *serverURL,
		CACertPath: *tlsCA,
		Insecure:   *insecure,
	})

	// Создаем сервисы
	authService := auth.NewAuthService(apiClient, boltStorage)
	dataService := data.NewService(boltStorage)
	syncService := sync.NewService(apiClient, boltStorage, boltStorage, logger)

	// Создаем CLI с сервисами (без прямого доступа к storage)
	commands := cli.New(apiClient, authService, dataService, syncService, &pass)

	command := args[0]
	if command != "login" {
		errPass := commands.ReadMasterPassword(ctx)
		if errPass != nil {
			fmt.Fprintf(os.Stderr, "Failed to read master password: %v\n", errPass)
			os.Exit(1)
		}
	}

	commands.Run(ctx, args)
}

func printVersion() {
	fmt.Printf("GophKeeper Client\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
}
