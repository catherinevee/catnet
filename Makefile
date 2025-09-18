.PHONY: help install dev-install test lint format clean docker-build docker-up docker-down migrate docs

# Default target
help:
	@echo "CatNet - Network Configuration Deployment System"
	@echo ""
	@echo "Available commands:"
	@echo "  make install       Install production dependencies"
	@echo "  make dev-install   Install development dependencies"
	@echo "  make test          Run tests with coverage"
	@echo "  make lint          Run all linters"
	@echo "  make format        Format code with black"
	@echo "  make clean         Clean up generated files"
	@echo "  make docker-build  Build Docker images"
	@echo "  make docker-up     Start Docker services"
	@echo "  make docker-down   Stop Docker services"
	@echo "  make migrate       Run database migrations"
	@echo "  make docs          Build documentation"
	@echo "  make run           Run the application"
	@echo "  make cli           Run CLI interface"

# Installation
install:
	pip install -e .

dev-install:
	pip install -e ".[dev,docs]"
	pre-commit install

# Testing
test:
	pytest tests/ -v --cov=src --cov-report=html --cov-report=term

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

test-security:
	bandit -r src/
	safety check

# Code quality
lint:
	flake8 src/ tests/
	mypy src/
	pylint src/
	bandit -r src/

format:
	black src/ tests/ scripts/
	isort src/ tests/ scripts/

check-format:
	black --check src/ tests/ scripts/
	isort --check-only src/ tests/ scripts/

# Cleaning
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/

# Docker
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-clean:
	docker-compose down -v
	docker system prune -f

# Database
migrate:
	alembic upgrade head

migrate-create:
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"

migrate-rollback:
	alembic downgrade -1

db-reset:
	alembic downgrade base
	alembic upgrade head

# Documentation
docs:
	cd docs && sphinx-build -b html . _build/html

docs-serve:
	cd docs && python -m http.server --directory _build/html

# Running
run:
	uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

run-prod:
	gunicorn src.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

cli:
	python catnet_cli.py

# Development
dev:
	tmux new-session -d -s catnet 'make run' \; \
	split-window -h 'make docker-up' \; \
	split-window -v 'watch make test' \; \
	attach

# Security
vault-init:
	@echo "Initializing HashiCorp Vault..."
	vault operator init -key-shares=5 -key-threshold=3

vault-unseal:
	@echo "Unsealing Vault..."
	vault operator unseal

generate-certs:
	python scripts/generate_ca.py

# Deployment
deploy-dev:
	@echo "Deploying to development environment..."
	ansible-playbook -i ansible/inventory/dev ansible/deploy.yml

deploy-staging:
	@echo "Deploying to staging environment..."
	ansible-playbook -i ansible/inventory/staging ansible/deploy.yml

deploy-prod:
	@echo "Deploying to production environment..."
	@echo "WARNING: This will deploy to production. Are you sure? [y/N]"
	@read -p "" confirm; \
	if [ "$$confirm" = "y" ]; then \
		ansible-playbook -i ansible/inventory/prod ansible/deploy.yml; \
	fi

# CI/CD
ci:
	@echo "Running CI pipeline..."
	make lint
	make test
	make docker-build