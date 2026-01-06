.PHONY: build run test clean docker-build docker-push lint fmt tidy

# Variables
APP_NAME := vigilancex
VERSION := 1.0.0
GO := go
DOCKER := docker

# Build targets
build:
	$(GO) build -ldflags="-w -s -X main.version=$(VERSION)" -o bin/$(APP_NAME)-api ./cmd/api
	$(GO) build -ldflags="-w -s -X main.version=$(VERSION)" -o bin/$(APP_NAME)-detect2ban ./cmd/detect2ban

build-api:
	$(GO) build -ldflags="-w -s -X main.version=$(VERSION)" -o bin/$(APP_NAME)-api ./cmd/api

build-detect2ban:
	$(GO) build -ldflags="-w -s -X main.version=$(VERSION)" -o bin/$(APP_NAME)-detect2ban ./cmd/detect2ban

# Run targets
run-api:
	$(GO) run ./cmd/api

run-detect2ban:
	$(GO) run ./cmd/detect2ban

# Test targets
test:
	$(GO) test -v -race -cover ./...

test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Lint and format
lint:
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...
	goimports -w .

# Dependencies
tidy:
	$(GO) mod tidy
	$(GO) mod verify

download:
	$(GO) mod download

# Docker targets
docker-build:
	$(DOCKER) build -t $(APP_NAME)-api:$(VERSION) -f Dockerfile .
	$(DOCKER) build -t $(APP_NAME)-detect2ban:$(VERSION) -f Dockerfile.detect2ban .

docker-build-api:
	$(DOCKER) build -t $(APP_NAME)-api:$(VERSION) -f Dockerfile .

docker-build-detect2ban:
	$(DOCKER) build -t $(APP_NAME)-detect2ban:$(VERSION) -f Dockerfile.detect2ban .

# Clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Development helpers
dev:
	air -c .air.toml

generate:
	$(GO) generate ./...

# Database migrations (for future use)
migrate-up:
	@echo "Running migrations..."

migrate-down:
	@echo "Rolling back migrations..."

# Help
help:
	@echo "Available targets:"
	@echo "  build           - Build all binaries"
	@echo "  build-api       - Build API binary"
	@echo "  build-detect2ban - Build Detect2Ban binary"
	@echo "  run-api         - Run API server"
	@echo "  run-detect2ban  - Run Detect2Ban engine"
	@echo "  test            - Run tests"
	@echo "  test-coverage   - Run tests with coverage"
	@echo "  lint            - Run linter"
	@echo "  fmt             - Format code"
	@echo "  tidy            - Tidy dependencies"
	@echo "  docker-build    - Build Docker images"
	@echo "  clean           - Clean build artifacts"
	@echo "  dev             - Run with hot reload (requires air)"
