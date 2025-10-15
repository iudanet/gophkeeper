package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iudanet/gophkeeper/internal/server/handlers"
	"github.com/iudanet/gophkeeper/internal/server/storage/sqlite"
)

var (
	// Version information set via ldflags during build
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Parse flags
	showVersion := flag.Bool("version", false, "Show version information")
	port := flag.Int("port", 8080, "Server port")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	dbPath := flag.String("db", "gophkeeper.db", "Path to SQLite database file")
	jwtSecret := flag.String("jwt-secret", "", "JWT secret (auto-generated if empty)")
	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	// Инициализация logger
	logger := initLogger(*logLevel)
	logger.Info("Starting GophKeeper Server",
		slog.String("version", Version),
		slog.String("build_date", BuildDate),
		slog.String("git_commit", GitCommit),
		slog.Int("port", *port),
		slog.String("db_path", *dbPath),
	)

	// Генерируем JWT secret если не указан
	secret := *jwtSecret
	if secret == "" {
		logger.Warn("JWT secret not provided, generating random secret")
		secret = generateRandomSecret()
		logger.Info("Generated JWT secret (save this for production)", slog.String("secret", secret))
	}

	// Инициализация storage
	ctx := context.Background()
	storage, err := sqlite.New(ctx, *dbPath)
	if err != nil {
		logger.Error("Failed to initialize storage", slog.Any("error", err))
		os.Exit(1)
	}
	defer func() {
		if err := storage.Close(); err != nil {
			logger.Error("Failed to close storage", slog.Any("error", err))
		}
	}()
	logger.Info("Storage initialized successfully")

	// Создание JWT конфигурации
	// Access token: 15 минут, Refresh token: 30 дней
	jwtConfig := handlers.JWTConfig{
		Secret:          []byte(secret),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}
	logger.Info("JWT configuration initialized")

	// Создание handlers
	authHandler := handlers.NewAuthHandler(logger, storage, storage, jwtConfig)
	healthHandler := handlers.NewHealthHandler(logger)

	// Настройка роутинга с использованием net/http.ServeMux (Go 1.22+)
	mux := http.NewServeMux()

	// Auth endpoints
	mux.HandleFunc("POST /api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("GET /api/v1/auth/salt/{username}", authHandler.GetSalt)
	mux.HandleFunc("POST /api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /api/v1/auth/logout", authHandler.Logout)

	// Health check
	mux.HandleFunc("GET /api/v1/health", healthHandler.Health)

	// Создание HTTP сервера
	addr := fmt.Sprintf(":%d", *port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Запуск сервера в отдельной горутине
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("Server listening", slog.String("address", addr))
		serverErrors <- server.ListenAndServe()
	}()

	// Graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.Error("Server failed to start", slog.Any("error", err))
		os.Exit(1)
	case sig := <-shutdown:
		logger.Info("Server shutdown initiated", slog.String("signal", sig.String()))

		// Создаем контекст с таймаутом для graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown failed", slog.Any("error", err))
			if err := server.Close(); err != nil {
				logger.Error("Server close failed", slog.Any("error", err))
			}
			os.Exit(1)
		}

		logger.Info("Server stopped gracefully")
	}
}

// initLogger инициализирует структурированный logger
func initLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	// Используем JSON handler для production
	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}

func printVersion() {
	fmt.Printf("GophKeeper Server\n")
	fmt.Printf("Version:    %s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
}

// generateRandomSecret генерирует случайный секрет для JWT
func generateRandomSecret() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(fmt.Sprintf("failed to generate random secret: %v", err))
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
