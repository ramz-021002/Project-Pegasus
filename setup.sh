#!/bin/bash
# Setup script for Project Pegasus

set -e

echo "Project Pegasus Setup"
echo "======================="

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose (v2)
if ! docker compose version &> /dev/null; then
    echo "Error: Docker Compose (v2) is not installed (as 'docker compose')"
    echo "Please install Docker Compose v2: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "Docker and Docker Compose found"

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo ""
    echo "Creating .env file from template..."
    cp .env.example .env

    # Generate random keys
    SECRET_KEY=$(openssl rand -hex 32)
    ENCRYPTION_KEY=$(openssl rand -base64 32)

    # Update .env file
    sed -i.bak "s/SECRET_KEY=changeme.*/SECRET_KEY=$SECRET_KEY/" .env
    sed -i.bak "s/ENCRYPTION_KEY=changeme.*/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env
    rm .env.bak

    echo ".env file created with random keys"
else
    echo ".env file already exists"
fi

# Build Docker images
echo ""
echo "Building Docker images..."
./build-images.sh

# Start services
echo ""
read -p "Do you want to start the services now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Starting services..."
    docker compose up -d

    echo ""
    echo "Waiting for services to be ready..."
    sleep 10

    # Check health
    if curl -s http://localhost:8000/health > /dev/null; then
        echo "Services are running!"
    else
        echo "Services may still be starting up..."
    fi

    echo ""
    echo "Access points:"
    echo "  - API Documentation: http://localhost:8000/api/docs"
    echo "  - Health Check: http://localhost:8000/health"
    echo "  - Web Interface: Open frontend/index.html in your browser"
    echo ""
    echo "Useful commands:"
    echo "  - View logs: docker compose logs -f"
    echo "  - Stop services: docker compose down"
    echo "  - Restart services: docker compose restart"
fi

echo ""
echo "Setup complete!"
