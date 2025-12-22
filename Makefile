.PHONY: all build run test clean docker-build docker-up docker-down migrate migrate-up migrate-down migrate-down-all migrate-create migrate-version migrate-force lint postman openapi openapi-validate openapi-gen

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
		PGPASSWORD=$(SINGLE_AUTH_DB_PASSWORD) psql -h $(SINGLE_AUTH_DB_HOST) -U $(SINGLE_AUTH_DB_USER) -d $(SINGLE_AUTH_DB_NAME) -f $$f; \
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
SINGLE_AUTH_DB_HOST ?= single-auth-postgres-db.leetcoders.uz
SINGLE_AUTH_DB_PORT ?= 5500
SINGLE_AUTH_DB_USER ?= single_auth
SINGLE_AUTH_DB_PASSWORD ?= single_auth_secret_password
SINGLE_AUTH_DB_NAME ?= single_auth_service_db
SINGLE_AUTH_DB_SSL_MODE ?= disable

# Migration database URL
DATABASE_URL = postgres://single_auth:single_auth_secret_password@single-auth-postgres-db.leetcoders.uz:5500/single_auth_service_db?sslmode=disable

## migrate-up: Run all pending migrations
migrate-up:
	@echo "Running migrations up..."
	migrate -path migrations -database "$(DATABASE_URL)" up
	@echo "Migrations complete."

## migrate-down: Rollback the last migration
migrate-down:
	@echo "Rolling back last migration..."
	migrate -path migrations -database "$(DATABASE_URL)" down 1
	@echo "Rollback complete."

## migrate-down-all: Rollback all migrations
migrate-down-all:
	@echo "Rolling back all migrations..."
	migrate -path migrations -database "$(DATABASE_URL)" down -all
	@echo "Rollback complete."

## migrate-create: Create a new migration (usage: make migrate-create NAME=create_table)
migrate-create:
	@if [ -z "$(NAME)" ]; then echo "Usage: make migrate-create NAME=migration_name"; exit 1; fi
	migrate create -ext sql -dir migrations -seq $(NAME)
	@echo "Created new migration: $(NAME)"

## migrate-version: Show current migration version
migrate-version:
	@migrate -path migrations -database "$(DATABASE_URL)" version

## migrate-force: Force set migration version (usage: make migrate-force VERSION=1)
migrate-force:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make migrate-force VERSION=1"; exit 1; fi
	migrate -path migrations -database "$(DATABASE_URL)" force $(VERSION)

# Postman collection settings
POSTMAN_COLLECTION_NAME ?= Single Auth Service API
POSTMAN_BASE_URL ?= http://localhost:8080

# OpenAPI settings
OPENAPI_INPUT ?= api/openapi.yaml
OPENAPI_OUTPUT_JSON ?= api/openapi.json

## openapi: Generate OpenAPI JSON from YAML specification
openapi:
	@echo "Generating OpenAPI specification..."
	$(GOCMD) run ./scripts/openapi-gen/main.go \
		-input $(OPENAPI_INPUT) \
		-output $(OPENAPI_OUTPUT_JSON) \
		-format json
	@echo "Generated: $(OPENAPI_OUTPUT_JSON)"

## openapi-validate: Validate OpenAPI specification
openapi-validate:
	@echo "Validating OpenAPI specification..."
	$(GOCMD) run ./scripts/openapi-gen/main.go \
		-input $(OPENAPI_INPUT) \
		-validate

## openapi-gen: Generate Go types, server interface, and client from OpenAPI spec
openapi-gen: openapi
	@echo "Generating Go code from OpenAPI specification..."
	oapi-codegen -generate types,gin,client,spec \
		-package generated \
		-o internal/generated/openapi.go \
		$(OPENAPI_OUTPUT_JSON)
	@echo "Generated: internal/generated/openapi.go"
	$(GOMOD) tidy
