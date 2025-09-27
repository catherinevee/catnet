# CatNet Makefile
# Comprehensive build, test, and deployment automation

.PHONY: help install install-dev clean test test-unit test-integration test-security test-performance test-e2e
.PHONY: lint format type-check security-scan coverage run run-dev build docker-build docker-run
.PHONY: db-migrate db-reset docs deploy-local deploy-staging deploy-production backup

# Default target
help: ## Show this help message
	@echo "CatNet - Network Configuration Deployment System"
	@echo "=================================================="
	@echo ""
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Installation targets
install: ## Install production dependencies
	pip install -r requirements.txt

install-dev: ## Install development dependencies
	pip install -r requirements-dev.txt
	pre-commit install

# Cleaning targets
clean: ## Clean up build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf test-reports
	rm -rf dist
	rm -rf build

# Testing targets
test: ## Run all tests
	python tests/test_runner.py all

test-unit: ## Run unit tests only
	python tests/test_runner.py unit

test-integration: ## Run integration tests only
	python tests/test_runner.py integration

test-security: ## Run security tests only
	python tests/test_runner.py security

test-performance: ## Run performance tests only
	python tests/test_runner.py performance

test-e2e: ## Run end-to-end tests only
	python tests/test_runner.py e2e

test-quick: ## Run quick tests (skip slow ones)
	python tests/test_runner.py all --skip-slow

test-specific: ## Run specific test (usage: make test-specific TEST=path/to/test)
	python tests/test_runner.py --test $(TEST)

coverage: ## Generate coverage report
	python tests/test_runner.py --coverage-only

# Code quality targets
lint: ## Run linting checks
	flake8 src tests
	black --check src tests
	isort --check-only src tests

format: ## Format code
	black src tests
	isort src tests

type-check: ## Run type checking
	mypy src --strict

security-scan: ## Run security scanning
	bandit -r src/
	safety check
	semgrep --config=auto src/

quality: lint type-check security-scan ## Run all code quality checks

# Development targets
run: ## Run the application (production mode)
	uvicorn src.api.main:app --host 0.0.0.0 --port 8080

run-dev: ## Run the application (development mode)
	uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --reload

run-debug: ## Run the application with debugging
	python -m debugpy --listen 5678 --wait-for-client -m uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --reload

# Docker targets
docker-build: ## Build Docker image
	docker build -t catnet:latest .

docker-build-dev: ## Build Docker image for development
	docker build --target development -t catnet:dev .

docker-run: ## Run Docker container
	docker run -p 8080:8080 catnet:latest

docker-compose-up: ## Start all services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop all services
	docker-compose down

docker-compose-logs: ## View logs from all services
	docker-compose logs -f

# Database targets
db-migrate: ## Run database migrations
	alembic upgrade head

db-migrate-create: ## Create new migration (usage: make db-migrate-create MSG="description")
	alembic revision --autogenerate -m "$(MSG)"

db-reset: ## Reset database (WARNING: destroys all data)
	alembic downgrade base
	alembic upgrade head

db-seed: ## Seed database with test data
	python scripts/seed_database.py

# Documentation targets
docs: ## Generate documentation
	sphinx-build -b html docs/ docs/_build/html

docs-serve: ## Serve documentation locally
	cd docs/_build/html && python -m http.server 8000

# Deployment targets
deploy-local: ## Deploy to local environment
	@echo "Deploying to local environment..."
	docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d

deploy-staging: ## Deploy to staging environment
	@echo "Deploying to staging environment..."
	# Add staging deployment commands here

deploy-production: ## Deploy to production environment
	@echo "Deploying to production environment..."
	# Add production deployment commands here

# Backup targets
backup: ## Create backup of database and configurations
	@echo "Creating backup..."
	mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	# Add backup commands here

restore: ## Restore from backup (usage: make restore BACKUP=backup_name)
	@echo "Restoring from backup: $(BACKUP)"
	# Add restore commands here

# Monitoring and maintenance
health-check: ## Check system health
	curl -f http://localhost:8080/health || exit 1

logs: ## View application logs
	tail -f logs/catnet.log

metrics: ## View metrics endpoint
	curl http://localhost:8080/metrics

# Development workflow targets
dev-setup: install-dev db-migrate db-seed ## Setup development environment
	@echo "Development environment setup complete!"

ci-test: clean install-dev lint type-check security-scan test ## Run CI test pipeline
	@echo "CI pipeline completed successfully!"

pre-commit: lint type-check test-unit ## Run pre-commit checks
	@echo "Pre-commit checks passed!"

release-check: clean install lint type-check security-scan test ## Full release validation
	@echo "Release validation completed!"

# Utility targets
requirements-update: ## Update requirements files
	pip-compile requirements.in
	pip-compile requirements-dev.in

check-deps: ## Check for dependency vulnerabilities
	safety check
	pip-audit

env-check: ## Check environment configuration
	python tests/test_runner.py --check-only

vault-init: ## Initialize Vault for development
	@echo "Initializing Vault..."
	# Add Vault initialization commands

vault-unseal: ## Unseal Vault
	@echo "Unsealing Vault..."
	# Add Vault unseal commands

# Kubernetes targets (if using K8s)
k8s-deploy: ## Deploy to Kubernetes
	kubectl apply -f k8s/

k8s-delete: ## Delete from Kubernetes
	kubectl delete -f k8s/

k8s-logs: ## View Kubernetes logs
	kubectl logs -f deployment/catnet-api

k8s-port-forward: ## Port forward to Kubernetes service
	kubectl port-forward service/catnet-api 8080:8080

# Performance and load testing
load-test: ## Run load tests
	locust -f tests/performance/locustfile.py --host=http://localhost:8080

stress-test: ## Run stress tests
	python tests/test_runner.py performance

benchmark: ## Run benchmarks
	pytest tests/performance/ --benchmark-only --benchmark-json=benchmark-results.json

# Git hooks and workflow
git-hooks: ## Install git hooks
	pre-commit install
	pre-commit install --hook-type commit-msg

git-check: ## Check git status and branch
	@git status
	@echo "Current branch: $$(git branch --show-current)"

# Configuration management
config-validate: ## Validate configuration files
	python -c "from configs.settings import get_settings; get_settings()"

config-encrypt: ## Encrypt sensitive configuration files
	@echo "Encrypting configuration files..."
	# Add encryption commands

config-decrypt: ## Decrypt configuration files
	@echo "Decrypting configuration files..."
	# Add decryption commands

# Certificate management
cert-generate: ## Generate self-signed certificates for development
	openssl req -x509 -newkey rsa:4096 -keyout configs/nginx/ssl/catnet.key -out configs/nginx/ssl/catnet.crt -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=CatNet/CN=catnet.local"

cert-check: ## Check certificate expiration
	openssl x509 -in configs/nginx/ssl/catnet.crt -text -noout | grep "Not After"

# Troubleshooting targets
debug-info: ## Show debug information
	@echo "System Information:"
	@echo "==================="
	@python --version
	@echo "Docker version: $$(docker --version)"
	@echo "Docker Compose version: $$(docker-compose --version)"
	@echo "Git version: $$(git --version)"
	@echo ""
	@echo "Environment Variables:"
	@echo "====================="
	@env | grep CATNET || echo "No CATNET environment variables set"

troubleshoot: ## Run troubleshooting checks
	@echo "Running troubleshooting checks..."
	@make health-check || echo "Health check failed"
	@make env-check || echo "Environment check failed"
	@docker ps | grep catnet || echo "No CatNet containers running"

# Special targets for CI/CD
ci-setup: ## Setup CI environment
	pip install -r requirements-dev.txt

ci-lint: ## CI linting (with JUnit output)
	flake8 src tests --format=junit-xml --output-file=test-reports/flake8.xml

ci-security: ## CI security scanning (with JSON output)
	bandit -r src/ -f json -o test-reports/bandit.json

ci-coverage: ## CI coverage reporting
	coverage xml -o test-reports/coverage.xml

# Version management
version-show: ## Show current version
	@python -c "from src.api.main import app; print(app.version)"

version-bump-patch: ## Bump patch version
	@echo "Bumping patch version..."
	# Add version bumping logic

version-bump-minor: ## Bump minor version
	@echo "Bumping minor version..."
	# Add version bumping logic

version-bump-major: ## Bump major version
	@echo "Bumping major version..."
	# Add version bumping logic

# Project information
info: ## Show project information
	@echo "CatNet - Network Configuration Deployment System"
	@echo "================================================"
	@echo "Version: $$(make version-show)"
	@echo "Environment: $$(python -c 'from configs.settings import get_settings; print(get_settings().ENVIRONMENT.value)')"
	@echo "Debug Mode: $$(python -c 'from configs.settings import get_settings; print(get_settings().DEBUG)')"
	@echo "Security Level: $$(python -c 'from configs.settings import get_settings; print(get_settings().SECURITY_LEVEL.value)')"
	@echo ""
	@echo "Quick Commands:"
	@echo "  make dev-setup    - Setup development environment"
	@echo "  make run-dev      - Run in development mode"
	@echo "  make test         - Run all tests"
	@echo "  make format       - Format code"
	@echo "  make quality      - Run code quality checks"