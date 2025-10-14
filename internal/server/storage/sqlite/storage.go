package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // SQLite driver
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// Storage represents SQLite storage implementation
type Storage struct {
	db *sql.DB
}

// New creates a new SQLite storage instance
// dbPath is the path to the SQLite database file
// Use ":memory:" for in-memory database (useful for testing)
func New(ctx context.Context, dbPath string) (*Storage, error) {
	// Открываем соединение с БД
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Проверяем соединение
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Настраиваем connection pool
	// SQLite с WAL mode может поддерживать несколько читателей, но только одного писателя
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Включаем WAL mode и другие оптимизации
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
	}

	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	storage := &Storage{db: db}

	// Запускаем миграции
	if err := storage.runMigrations(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return storage, nil
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// runMigrations выполняет миграции из embedded FS
func (s *Storage) runMigrations() error {
	// Устанавливаем dialect для SQLite
	goose.SetDialect("sqlite3")

	// Устанавливаем источник миграций из embedded FS
	goose.SetBaseFS(embedMigrations)

	// Запускаем миграции
	if err := goose.Up(s.db, "migrations"); err != nil {
		return fmt.Errorf("goose up failed: %w", err)
	}

	return nil
}

// DB returns the underlying database connection for testing purposes
func (s *Storage) DB() *sql.DB {
	return s.db
}
