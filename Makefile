# Makefile for ks-tool

# Variables
BINARY_NAME=ks-tool
BINARY_NAME_LINUX=ks
MAIN_FILE=main.go
VERSION?=$(shell date +%Y%m%d-%H%M%S)
BUILD_TIME=$(shell date +%Y-%m-%d\ %H:%M:%S)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DIR=build

# Build flags
LDFLAGS=-ldflags "-X 'github.com/xuehaipeng/ks-tool/pkg/version.Version=$(VERSION)' \
		-X 'github.com/xuehaipeng/ks-tool/pkg/version.BuildTime=$(BUILD_TIME)' \
		-X 'github.com/xuehaipeng/ks-tool/pkg/version.GitCommit=$(GIT_COMMIT)'"

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME_LINUX) $(MAIN_FILE)

# Clean build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME_LINUX)
	rm -f $(BINARY_NAME)-*

# Run tests
.PHONY: test
test:
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Vet code
.PHONY: vet
vet:
	go vet ./...

# Install dependencies
.PHONY: deps
deps:
	go mod download
	go mod tidy

# Install binary to GOPATH/bin
.PHONY: install
install:
	go install

# Run the application (for testing)
.PHONY: run
run:
	go run $(MAIN_FILE)

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build for Linux (creates 'ks' binary)"
	@echo "  clean        - Remove build artifacts"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code (requires golangci-lint)"
	@echo "  vet          - Vet code"
	@echo "  deps         - Install and tidy dependencies"
	@echo "  install      - Install binary to GOPATH/bin"
	@echo "  run          - Run the application"
	@echo "  help         - Show this help message"

# Development targets
.PHONY: dev
dev: deps fmt vet test build

# Release preparation
.PHONY: release
release: clean deps fmt vet test build 