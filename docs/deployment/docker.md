# Docker Deployment Guide

## Overview

This guide covers deploying Intellicrack using Docker containers. Docker provides a consistent environment across different systems and simplifies deployment.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+ (optional)
- 8GB RAM minimum
- 20GB free disk space

## Quick Start

### Using Docker Compose

1. Clone the repository:
```batch
git clone https://github.com/yourusername/intellicrack.git
cd intellicrack
```

2. Start services:
```batch
docker-compose up -d
```

3. Access the application:
- Web UI: http://localhost:8080
- API: http://localhost:9999

### Using Docker CLI

1. Build the image:
```batch
docker build -t intellicrack:latest .
```

2. Run the container:
```batch
docker run -d ^
  --name intellicrack ^
  -p 8080:8080 ^
  -p 9999:9999 ^
  -v %cd%\data:/app/data ^
  -v %cd%\logs:/app/logs ^
  intellicrack:latest
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `INTELLICRACK_CONFIG_PATH` | Config file path | `/app/config/intellicrack_config.json` |
| `INTELLICRACK_DEBUG` | Enable debug mode | `false` |
| `DB_PASSWORD` | PostgreSQL password | `intellicrack123` |
| `REDIS_PASSWORD` | Redis password | (none) |

### Volume Mounts

| Host Path | Container Path | Purpose |
|-----------|----------------|---------|
| `./data` | `/app/data` | Persistent data storage |
| `./logs` | `/app/logs` | Application logs |
| `./config` | `/app/config` | Configuration files |
| `./samples` | `/app/samples` | Binary samples (read-only) |
| `./cache` | `/app/cache` | Analysis cache |

### Network Configuration

The Docker Compose setup creates a bridge network `intellicrack_net` for inter-container communication.

Exposed ports:
- `8080`: Web UI
- `9999`: Plugin system API
- `4444`: C2 server
- `5432`: PostgreSQL (optional)
- `6379`: Redis (optional)

## Advanced Configuration

### Custom Dockerfile

For custom builds, modify the Dockerfile:

```dockerfile
# Add custom tools
RUN apt-get update && apt-get install -y \
    my-custom-tool \
    && rm -rf /var/lib/apt/lists/*

# Install additional Python packages
RUN pip install --no-cache-dir \
    my-custom-package==1.0.0
```

### GPU Support

For GPU acceleration:

```yaml
services:
  intellicrack:
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
```

### Multi-Container Setup

Production deployment with all services:

```yaml
version: '3.8'

services:
  intellicrack:
    image: intellicrack:latest
    depends_on:
      - postgres
      - redis
    environment:
      - DATABASE_URL=postgresql://intellicrack:${DB_PASSWORD}@postgres/intellicrack
      - REDIS_URL=redis://redis:6379

  postgres:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  radare2:
    image: radare/radare2:latest
    volumes:
      - ./samples:/samples:ro

volumes:
  postgres_data:
  redis_data:
```

## Security Considerations

### Running as Non-Root

The container runs as the `intellicrack` user by default. Ensure proper permissions:

```bash
# Fix permissions on host
chown -R 1000:1000 ./data ./logs ./cache
```

### Network Isolation

For production, use custom networks:

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true
```

### Secret Management

Use Docker secrets for sensitive data:

```yaml
secrets:
  db_password:
    file: ./secrets/db_password.txt

services:
  intellicrack:
    secrets:
      - db_password
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
```

## Performance Tuning

### Resource Limits

Set appropriate resource limits:

```yaml
services:
  intellicrack:
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

### Shared Memory

For large file analysis:

```yaml
services:
  intellicrack:
    shm_size: '2gb'
```

### Storage Driver

Use appropriate storage drivers:

```bash
# Check current driver
docker info | grep "Storage Driver"

# For better performance with many layers
DOCKER_STORAGE_OPTIONS="--storage-driver overlay2"
```

## Monitoring

### Health Checks

```yaml
services:
  intellicrack:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Logging

Configure logging drivers:

```yaml
services:
  intellicrack:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "5"
```

### Metrics

Export metrics for monitoring:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
```

## Backup and Recovery

### Backup Volumes

```bash
# Backup data
docker run --rm \
  -v intellicrack_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/data-$(date +%Y%m%d).tar.gz -C /data .

# Restore data
docker run --rm \
  -v intellicrack_data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar xzf /backup/data-20250616.tar.gz -C /data
```

### Database Backup

```bash
# Backup PostgreSQL
docker-compose exec postgres pg_dump -U intellicrack intellicrack > backup.sql

# Restore PostgreSQL
docker-compose exec -T postgres psql -U intellicrack intellicrack < backup.sql
```

## Troubleshooting

### Common Issues

1. **Container won't start**
   ```bash
   # Check logs
   docker logs intellicrack

   # Interactive debug
   docker run -it --rm intellicrack:latest /bin/bash
   ```

2. **Permission denied**
   ```bash
   # Fix ownership
   docker exec intellicrack chown -R intellicrack:intellicrack /app/data
   ```

3. **Out of memory**
   ```bash
   # Increase memory limit
   docker update --memory 16g intellicrack
   ```

### Debug Mode

Enable debug logging:
```bash
docker run -e INTELLICRACK_DEBUG=true intellicrack:latest
```

### Shell Access

```bash
# Access running container
docker exec -it intellicrack /bin/bash

# Run as root for debugging
docker exec -it -u root intellicrack /bin/bash
```

## Production Deployment

### Docker Swarm

Deploy as a service:
```bash
docker service create \
  --name intellicrack \
  --replicas 3 \
  --publish 8080:8080 \
  --mount type=volume,source=data,target=/app/data \
  intellicrack:latest
```

### Kubernetes

See the [Kubernetes deployment guide](kubernetes.md) for container orchestration.

### Cloud Deployment

- **AWS ECS**: Use the provided task definition
- **Azure Container Instances**: Deploy using ARM template
- **Google Cloud Run**: Deploy serverless containers

## Maintenance

### Updates

```bash
# Pull latest image
docker pull intellicrack:latest

# Recreate container
docker-compose up -d --force-recreate
```

### Cleanup

```bash
# Remove stopped containers
docker container prune

# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune
```
