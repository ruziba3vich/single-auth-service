.PHONY: all build run test clean docker-build docker-up docker-down migrate lint postman

# Variables
BINARY_NAME=auth-service
MAIN_PATH=./cmd/server
DOCKER_IMAGE=auth-service:latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-w -s"

all: build

## build: Build the application
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PATH)

## run: Run the application
run: build
	./$(BINARY_NAME)

## test: Run tests
test:
	$(GOTEST) -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

## deps: Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

## lint: Run linter
lint:
	golangci-lint run ./...

## docker-build: Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE) .

## docker-up: Start all services with Docker Compose
docker-up:
	docker-compose up -d

## docker-down: Stop all services
docker-down:
	docker-compose down

## docker-logs: View Docker Compose logs
docker-logs:
	docker-compose logs -f

## migrate: Run database migrations
migrate:
	@echo "Running migrations..."
	@for f in migrations/*.sql; do \
		echo "Applying $$f..."; \
		PGPASSWORD=$(DB_PASSWORD) psql -h $(DB_HOST) -U $(DB_USER) -d $(DB_NAME) -f $$f; \
	done
	@echo "Migrations complete."

## migrate-docker: Run migrations in Docker
migrate-docker:
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/000_init.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/001_create_users.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/002_create_user_identities.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/003_create_oauth_clients.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/004_create_user_devices.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/005_create_refresh_tokens.sql
	docker-compose exec postgres psql -U auth -d auth_service -f /docker-entrypoint-initdb.d/006_create_signing_keys.sql

## generate-client: Create a test OAuth client
generate-client:
	@echo "Creating test OAuth client..."
	curl -X POST http://localhost:8080/oauth/client \
		-H "Content-Type: application/json" \
		-d '{"name":"Test App","redirect_uris":["http://localhost:3000/callback"],"grant_types":["authorization_code","refresh_token"],"is_confidential":true}'

## postman: Generate Postman collection from handlers
postman:
	@echo "Generating Postman collection..."
	$(GOCMD) run ./scripts/postman-gen/main.go \
		-path ./internal/interfaces/http/handlers \
		-output postman_collection.json \
		-name "$(POSTMAN_COLLECTION_NAME)" \
		-base-url "$(POSTMAN_BASE_URL)"
	@echo "Generated: postman_collection.json"

## help: Display this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

# Default values for migration (override with environment variables)
DB_HOST ?= localhost
DB_USER ?= auth
DB_PASSWORD ?= auth_secret_password
DB_NAME ?= auth_service

# Postman collection settings
POSTMAN_COLLECTION_NAME ?= Single Auth Service API
POSTMAN_BASE_URL ?= http://localhost:8080
