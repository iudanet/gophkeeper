.PHONY: all build build-server build-client test test-unit test-integration fmt lint clean run-server run-client help

# Version information
VERSION ?= dev
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -X 'main.Version=$(VERSION)' -X 'main.BuildDate=$(BUILD_DATE)' -X 'main.GitCommit=$(GIT_COMMIT)'

# Build directories
BUILD_DIR := ./bin
SERVER_BIN := $(BUILD_DIR)/server
CLIENT_BIN := $(BUILD_DIR)/client

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOFMT := $(GOCMD) fmt
GOVET := $(GOCMD) vet

all: test build ## Run tests and build binaries

build: build-server build-client ## Build both server and client

build-server: ## Build server binary
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(SERVER_BIN) ./cmd/server

build-client: ## Build client binary
	@echo "Building client..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CLIENT_BIN) ./cmd/client

test: test-unit ## Run all tests

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	$(GOTEST) -v -race -tags=integration ./test/integration/...

coverage: test-unit ## Show test coverage
	@echo "Test coverage:"
	@$(GOCMD) tool cover -func=coverage.out

coverage-html: test-unit ## Generate HTML coverage report
	@echo "Generating HTML coverage report..."
	@$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format code with gofmt, goimports, and fieldalignment
	@echo "Running gofmt..."
	@gofmt -w .
	@echo "Running goimports..."
	@goimports -w .
	@echo "Running fieldalignment..."
	@$(GOCMD) run golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment -fix ./...

lint: ## Run linters
	@echo "Running go fmt..."
	@$(GOFMT) ./...
	@echo "Running go vet..."
	@$(GOVET) ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html
	@rm -f *.db *.db-shm *.db-wal

run-server: build-server ## Build and run server
	$(SERVER_BIN)

run-client: build-client ## Build and run client
	$(CLIENT_BIN)

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	@$(GOMOD) download
	@$(GOMOD) tidy

help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
