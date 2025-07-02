.PHONY: build run test clean docker-build docker-run dev deps lint fmt vet check-security test-jwt test-rate-limit test-circuit-breaker test-integration test-all

# Variables
BINARY_NAME=gateway
DOCKER_IMAGE=sentinel-gate
DOCKER_TAG=latest

# Build the application
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o bin/$(BINARY_NAME) cmd/gateway/main.go

# Run the application
run:
	@echo "Running $(BINARY_NAME)..."
	@go run cmd/gateway/main.go

# Run in development mode with hot reload (requires air)
dev:
	@echo "Starting development server with hot reload..."
	@air

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run unit tests
test:
	@echo "Running unit tests..."
	@go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -cover -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Run JWT authentication tests
test-jwt:
	@echo "Running JWT authentication tests..."
	@chmod +x test-jwt.sh
	@./test-jwt.sh

# Run rate limiting tests
test-rate-limit:
	@echo "Running rate limiting tests..."
	@chmod +x test-rate-limit.sh
	@./test-rate-limit.sh

# Run circuit breaker tests
test-circuit-breaker:
	@echo "Running circuit breaker tests..."
	@chmod +x test-circuit-breaker.sh
	@./test-circuit-breaker.sh

# Run all integration tests (.sh scripts)
test-integration:
	@echo "Running all integration tests..."
	@echo "========================================"
	@echo "1. JWT Authentication Tests"
	@echo "========================================"
	@chmod +x test-jwt.sh && ./test-jwt.sh
	@echo ""
	@echo "========================================"
	@echo "2. Rate Limiting Tests"
	@echo "========================================"
	@chmod +x test-rate-limit.sh && ./test-rate-limit.sh
	@echo ""
	@echo "========================================"
	@echo "3. Circuit Breaker Tests"
	@echo "========================================"
	@chmod +x test-circuit-breaker.sh && ./test-circuit-breaker.sh
	@echo ""
	@echo "✅ All integration tests completed!"

# Run ALL tests (unit + integration)
test-all: test test-integration
	@echo ""
	@echo "🎉 All tests (unit + integration) completed successfully!"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Vet code
vet:
	@echo "Vetting code..."
	@go vet ./...

# Lint code (requires golangci-lint)
lint:
	@echo "Linting code..."
	@golangci-lint run

# Security check (requires gosec)
check-security:
	@echo "Running security checks..."
	@gosec ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -rf build/
	@rm -rf coverage.out coverage.html

# Docker build
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Docker run
docker-run:
	@echo "Running Docker container..."
	@docker run -d \
		--name $(DOCKER_IMAGE) \
		-p 8080:8080 \
		-e JWT_SECRET=your-super-secret-jwt-key-with-at-least-32-characters \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

# Docker stop and remove
docker-stop:
	@echo "Stopping and removing Docker container..."
	@docker stop $(DOCKER_IMAGE) || true
	@docker rm $(DOCKER_IMAGE) || true

# Start all services with docker-compose
up:
	@echo "Starting all services..."
	@docker-compose up -d

# Stop all services
down:
	@echo "Stopping all services..."
	@docker-compose down

# View logs
logs:
	@echo "Viewing logs..."
	@docker-compose logs -f gateway

# Generate JWT secret
jwt-secret:
	@echo "Generating JWT secret..."
	@openssl rand -base64 32

# Install development tools
install-tools:
	@echo "Installing development tools..."
	@go install github.com/cosmtrek/air@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Run all checks
check: fmt vet lint test

# Prepare for commit
pre-commit: check build

# Show help
help:
	@echo "Available commands:"
	@echo ""
	@echo "📦 BUILD & RUN:"
	@echo "  build          - Build the application"
	@echo "  run            - Run the application"
	@echo "  dev            - Run in development mode with hot reload"
	@echo "  deps           - Install dependencies"
	@echo ""
	@echo "🧪 TESTING:"
	@echo "  test               - Run unit tests"
	@echo "  test-coverage      - Run tests with coverage"
	@echo "  test-jwt           - Run JWT authentication tests"
	@echo "  test-rate-limit    - Run rate limiting tests"
	@echo "  test-circuit-breaker - Run circuit breaker tests"
	@echo "  test-integration   - Run all integration tests (.sh scripts)"
	@echo "  test-all           - Run ALL tests (unit + integration)"
	@echo "  bench              - Run benchmarks"
	@echo ""
	@echo "🔍 CODE QUALITY:"
	@echo "  fmt            - Format code"
	@echo "  vet            - Vet code"
	@echo "  lint           - Lint code"
	@echo "  check-security - Run security checks"
	@echo "  check          - Run all checks"
	@echo "  pre-commit     - Prepare for commit"
	@echo ""
	@echo "🐳 DOCKER:"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-stop    - Stop Docker container"
	@echo "  up             - Start all services with docker-compose"
	@echo "  down           - Stop all services"
	@echo "  logs           - View logs"
	@echo ""
	@echo "🛠️  UTILITIES:"
	@echo "  jwt-secret     - Generate JWT secret"
	@echo "  install-tools  - Install development tools"
	@echo "  clean          - Clean build artifacts"
	@echo "  help           - Show this help" 