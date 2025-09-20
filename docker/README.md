# Docker Configuration

This directory contains Docker-related files:

- `Dockerfile` - Docker image definition for CatNet
- `docker-compose.yml` - Multi-container Docker application configuration

## Usage

```bash
# Build and run with docker-compose
cd ..  # Go to project root
docker-compose -f docker/docker-compose.yml up

# Build Docker image
docker build -f docker/Dockerfile -t catnet:latest .
```