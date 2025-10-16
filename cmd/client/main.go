package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/iudanet/gophkeeper/internal/client/api"
	"github.com/iudanet/gophkeeper/internal/client/cli"
	"github.com/iudanet/gophkeeper/internal/client/storage/boltdb"
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
		cli.PrintUsage()
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
		if err := cli.RunRegister(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if err := cli.RunLogin(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "logout":
		if err := cli.RunLogout(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := cli.RunStatus(ctx, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "add":
		if err := cli.RunAdd(ctx, args[1:], boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := cli.RunList(ctx, args[1:], boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "get":
		if err := cli.RunGet(ctx, args[1:], boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "delete":
		if err := cli.RunDelete(ctx, args[1:], boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := cli.RunSync(ctx, apiClient, boltStorage); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		cli.PrintUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("GophKeeper Client\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
}
