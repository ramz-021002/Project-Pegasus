#!/bin/bash
# Build Docker images for Project Pegasus analysis containers

set -e

echo "Building Project Pegasus Docker Images"
echo "=========================================="

# Change to project directory
cd "$(dirname "$0")"

# Build static analysis image
echo ""
echo "Building static analysis image..."
docker build -t pegasus-static-analysis:latest docker/static-analysis/

# Build dynamic analysis image
echo ""
echo "Building dynamic analysis image..."
docker build --no-cache -t pegasus-dynamic-analysis:latest docker/dynamic-analysis/

# Build network gateway image
echo ""
echo "Building network gateway image..."
docker build -t pegasus-network-gateway:latest docker/network-gateway/

echo ""
echo "All Docker images built successfully!"
echo ""
echo "Images created:"
docker images | grep pegasus

echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and configure settings"
echo "2. Run: docker compose up -d"
echo "3. Open http://localhost:8000/api/docs to see API documentation"
echo "4. Open frontend/index.html in a browser to use the web interface"