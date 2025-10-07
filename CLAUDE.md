# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GophKeeper is a client-server system for securely storing and synchronizing private data (credentials, passwords, binary data, bank card information, and other sensitive information).

**Key Requirements:**
- Use CRDT (Conflict-free Replicated Data Types) for synchronization
- Use BoltDB for client-side storage
- CLI application supporting Windows, Linux, and Mac OS
- Minimum 80% test coverage required
- All exported functions, types, variables, and packages must have comprehensive documentation

## Development Commands

### Building
```bash
# Build server
go build -o gophkeeper-server ./cmd/server

# Build client with version info
go build -ldflags "-X main.buildVersion=v1.0.0 -X 'main.buildDate=$(date)'" -o gophkeeper-client ./cmd/client
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage (minimum 80% required)
go test -cover ./...

# Run tests with coverage report
go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

# Run a specific test
go test -run TestName ./path/to/package

# Run tests with race detection
go test -race ./...
```

### Linting
```bash
# Run golangci-lint
golangci-lint run

# Run with auto-fix
golangci-lint run --fix
```

### Running
```bash
# Server
go run ./cmd/server

# Client
go run ./cmd/client
```

## Architecture

### Server Responsibilities
- User registration, authentication, and authorization
- Private data storage
- Data synchronization between multiple authorized clients of the same owner
- Serving private data to owner on request

### Client Responsibilities
- User authentication and authorization on remote server
- Local data storage and access
- Data synchronization with server
- CLI interface for data management

### Data Types Supported
1. **Login/Password pairs** - credentials storage
2. **Text data** - arbitrary text information
3. **Binary data** - files and binary content
4. **Bank card data** - card numbers, CVV, expiration dates
5. **Metadata** - arbitrary text metadata for any data type (website, person, bank, activation codes, etc.)

### Synchronization Strategy
- **CRDT** must be used for conflict-free synchronization between multiple clients
- **BoltDB** for client-side embedded storage
- Server handles conflict resolution using CRDT principles

### Project Structure
- `cmd/server/` - Server entry point
- `cmd/client/` - Client CLI entry point
- `internal/server/` - Server-specific logic
- `internal/client/` - Client-specific logic
- `internal/storage/` - Storage layer (BoltDB, server DB)
- `internal/crdt/` - CRDT implementation for synchronization
- `internal/crypto/` - Encryption/decryption utilities
- `pkg/` - Public/reusable packages
- `api/` - API definitions (gRPC/HTTP, optionally Swagger)

## Security Considerations

- All sensitive data must be encrypted before transmission and storage
- Use strong encryption algorithms (AES-256-GCM recommended)
- Implement proper key derivation (Argon2, PBKDF2, or scrypt)
- Never log sensitive data (passwords, keys, tokens, card numbers)
- Use TLS for all client-server communication
- Client must encrypt data locally before sending to server

## Optional Features

Consider implementing these optional features:
- OTP (One Time Password) support
- TUI (Terminal User Interface)
- Binary protocol (e.g., gRPC instead of HTTP/JSON)
- Functional and/or integration tests
- Swagger/OpenAPI documentation for API

## Build Versioning

Client must provide version and build date information:
```bash
gophkeeper-client --version
# Output: Version: v1.0.0, Build Date: 2025-10-07
```
