# Makefile for Project Pegasus

.PHONY: help setup start stop restart logs clean build test

help:
	@echo "🛡️  Project Pegasus - Available Commands"
	@echo ""
	@echo "Setup & Build:"
	@echo "  make setup        - Run initial setup (creates .env, builds images)"
	@echo "  make build        - Build all Docker images"
	@echo ""
	@echo "Service Control:"
	@echo "  make start        - Start all services"
	@echo "  make stop         - Stop all services"
	@echo "  make restart      - Restart all services"
	@echo "  make status       - Show service status"
	@echo ""
	@echo "Development:"
	@echo "  make logs         - View logs (all services)"
	@echo "  make logs-backend - View backend logs only"
	@echo "  make logs-celery  - View Celery worker logs"
	@echo "  make shell        - Open shell in backend container"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run test suite"
	@echo "  make test-upload  - Test sample upload"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean        - Clean up containers and volumes"
	@echo "  make clean-all    - Clean everything (including images)"
	@echo "  make backup-db    - Backup database"
	@echo ""
	@echo "Frontend:"
	@echo "  make frontend     - Open frontend in browser"

setup:
	@echo "Running setup script..."
	@bash ./setup.sh

build:
	@echo "Building Docker images..."
	@bash ./build-images.sh

start:
	@echo "Starting services..."
	@docker compose up -d
	@echo "Waiting for services..."
	@sleep 5
	@echo "Services started!"
	@make status

stop:
	@echo "Stopping services..."
	@docker compose down

restart:
	@echo "Restarting services..."
	@docker compose restart
	@echo "Services restarted!"

status:
	@echo "Service Status:"
	@docker compose ps
	@echo ""
	@echo "Health Check:"
	@curl -s http://localhost:8000/health | python3 -m json.tool || echo "Backend not responding"

logs:
	@docker compose logs -f --tail=100

logs-backend:
	@docker compose logs -f backend --tail=100

logs-celery:
	@docker compose logs -f celery-worker --tail=100

shell:
	@docker compose exec backend /bin/bash

test:
	@echo "Running tests..."
	@python3 test_system.py

test-upload:
	@echo "Testing sample upload..."
	@echo "test content" > /tmp/test_sample.bin
	@curl -X POST http://localhost:8000/api/upload/ -F "file=@/tmp/test_sample.bin"
	@rm /tmp/test_sample.bin

clean:
	@echo "Cleaning up containers and volumes..."
	@docker compose down -v
	@docker system prune -f
	@echo "Cleanup complete!"

clean-all: clean
	@echo "Removing Docker images..."
	@docker images | grep pegasus | awk '{print $$3}' | xargs docker rmi -f || true
	@echo "All cleaned up!"

backup-db:
	@echo "Backing up database..."
	@mkdir -p backups
	@docker compose exec -T postgres pg_dump -U pegasus pegasus_db > backups/backup_$$(date +%Y%m%d_%H%M%S).sql
	@echo "Database backed up to backups/"

frontend:
	@echo "Opening frontend..."
	@open frontend/index.html || xdg-open frontend/index.html || start frontend/index.html

dev-backend:
	@echo "Starting backend in development mode..."
	@cd backend && python -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python -m app.main

.PHONY: help setup build start stop restart status logs logs-backend logs-celery shell test test-upload clean clean-all backup-db frontend dev-backend
