# Production Deployment Guide

## Overview

This guide covers best practices and recommendations for deploying Intellicrack in production environments.

## System Requirements

### Minimum Requirements
- CPU: 8 cores (Intel/AMD x64)
- RAM: 16GB
- Storage: 100GB SSD
- OS: Windows 11 Pro/Enterprise or Windows Server 2022+

### Recommended Requirements
- CPU: 16+ cores
- RAM: 32GB+
- Storage: 500GB+ NVMe SSD
- GPU: NVIDIA GPU with 8GB+ VRAM (optional)
- Network: 1Gbps connection

## Pre-Deployment Checklist

### Security Hardening
- [ ] Update all Windows components
- [ ] Configure Windows Defender Firewall
- [ ] Set up SSL/TLS certificates
- [ ] Enable Windows audit logging
- [ ] Configure Windows Defender
- [ ] Set up Windows Advanced Threat Protection
- [ ] Implement rate limiting
- [ ] Configure backup strategy

### Infrastructure Setup
- [ ] Set up load balancer
- [ ] Configure database cluster
- [ ] Set up Redis cluster
- [ ] Configure monitoring
- [ ] Set up log aggregation
- [ ] Configure alerting
- [ ] Set up CI/CD pipeline
- [ ] Plan disaster recovery

## Installation Methods

### Windows Installation

#### Using Windows Installer
```batch
REM Download installer
curl -O https://github.com/yourusername/intellicrack/releases/latest/download/intellicrack-windows-x64.msi

REM Run installer silently
msiexec /i intellicrack-windows-x64.msi /quiet

REM Configure
intellicrack-config.exe setup
```

#### Manual Installation

```batch
REM Download release
curl -O https://github.com/yourusername/intellicrack/releases/latest/download/intellicrack-windows-x64.zip

REM Extract
Expand-Archive -Path intellicrack-windows-x64.zip -DestinationPath C:\Intellicrack

REM Install dependencies
cd C:\Intellicrack
pip install -r requirements\base.txt

REM Install as Windows Service
sc create Intellicrack binPath= "C:\Intellicrack\intellicrack-service.exe"
sc config Intellicrack start= auto
sc start Intellicrack
```

## Configuration

### Main Configuration

Edit `/etc/intellicrack/config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "workers": 4,
    "max_upload_size": "500MB"
  },
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "name": "intellicrack",
    "user": "intellicrack",
    "password": "${DB_PASSWORD}",
    "pool_size": 20,
    "max_overflow": 40
  },
  "cache": {
    "type": "redis",
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "password": "${REDIS_PASSWORD}"
  },
  "security": {
    "secret_key": "${SECRET_KEY}",
    "token_expiry": 3600,
    "max_login_attempts": 5,
    "enable_2fa": true
  },
  "analysis": {
    "timeout": 300,
    "max_file_size": "1GB",
    "sandbox_enabled": true,
    "parallel_jobs": 4
  }
}
```

### Environment Variables

Create `/etc/intellicrack/env`:

```bash
# Database
DB_PASSWORD=your_secure_password
DB_SSL_MODE=require

# Redis
REDIS_PASSWORD=your_redis_password

# Security
SECRET_KEY=your_secret_key_here
JWT_SECRET=your_jwt_secret

# API Keys (optional)
OPENAI_API_KEY=your_api_key
ANTHROPIC_API_KEY=your_api_key

# Performance
WORKERS=4
THREADS_PER_WORKER=2
MAX_MEMORY_PER_WORKER=4G
```

## Database Setup

### PostgreSQL

```sql
-- Create database and user
CREATE USER intellicrack WITH PASSWORD 'secure_password';
CREATE DATABASE intellicrack OWNER intellicrack;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE intellicrack TO intellicrack;

-- Performance tuning
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
ALTER SYSTEM SET work_mem = '50MB';
ALTER SYSTEM SET max_connections = 200;
```

### Run migrations
```bash
intellicrack-migrate upgrade head
```

### Redis

```bash
# Edit /etc/redis/redis.conf
maxmemory 4gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
requirepass your_redis_password
```

## Web Server Configuration

### Nginx Reverse Proxy

```nginx
upstream intellicrack {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
    server 127.0.0.1:8082;
    server 127.0.0.1:8083;
}

server {
    listen 80;
    server_name intellicrack.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name intellicrack.example.com;

    ssl_certificate /etc/ssl/certs/intellicrack.crt;
    ssl_certificate_key /etc/ssl/private/intellicrack.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 500M;
    client_body_timeout 300s;

    location / {
        proxy_pass http://intellicrack;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    location /ws {
        proxy_pass http://intellicrack;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## Performance Optimization

### System Tuning

Edit `/etc/sysctl.conf`:
```bash
# Network optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr

# File system
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Memory
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
```

### Process Limits

Edit `/etc/security/limits.conf`:
```bash
intellicrack soft nofile 65536
intellicrack hard nofile 65536
intellicrack soft nproc 32768
intellicrack hard nproc 32768
```

## Monitoring

### Prometheus Configuration

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'intellicrack'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

### Grafana Dashboard

Import the provided dashboard from `contrib/grafana/intellicrack-dashboard.json`

### Health Checks

```bash
# Add to crontab
*/5 * * * * /usr/local/bin/intellicrack-health-check || systemctl restart intellicrack
```

## Backup Strategy

### Automated Backups

```bash
#!/bin/bash
# /usr/local/bin/intellicrack-backup.sh

BACKUP_DIR="/backup/intellicrack"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backup
pg_dump -h localhost -U intellicrack intellicrack | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# File backup
tar -czf "$BACKUP_DIR/files_$DATE.tar.gz" /var/lib/intellicrack/data

# Config backup
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /etc/intellicrack

# Keep only last 30 days
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
```

Add to crontab:
```bash
0 2 * * * /usr/local/bin/intellicrack-backup.sh
```

## Security Best Practices

### API Security

1. **Rate Limiting**
```python
# Configure in settings
RATE_LIMIT = {
    'default': '100/hour',
    'analysis': '10/hour',
    'upload': '50/day'
}
```

2. **API Keys**
```bash
# Generate API key
intellicrack-cli api-key create --name "Production App" --scope read,write
```

3. **IP Whitelisting**
```json
{
  "security": {
    "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"],
    "api_key_required": true
  }
}
```

### File Upload Security

```python
# Configure allowed file types
ALLOWED_EXTENSIONS = {'.exe', '.dll', '.so', '.elf', '.dex', '.apk'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB
SCAN_UPLOADS = True
```

## High Availability

### Multi-Instance Setup

```bash
# Start multiple workers
for i in {1..4}; do
    intellicrack-worker --port 808$i --name worker$i &
done
```

### Load Balancer Health Checks

```python
# Health check endpoint
@app.route('/health')
def health_check():
    checks = {
        'database': check_db_connection(),
        'redis': check_redis_connection(),
        'disk_space': check_disk_space(),
        'memory': check_memory_usage()
    }

    if all(checks.values()):
        return jsonify({'status': 'healthy', 'checks': checks}), 200
    else:
        return jsonify({'status': 'unhealthy', 'checks': checks}), 503
```

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check for memory leaks: `intellicrack-debug memory`
   - Adjust worker memory limits
   - Enable memory profiling

2. **Slow Analysis**
   - Check CPU usage: `htop`
   - Monitor I/O: `iotop`
   - Review analysis logs

3. **Database Connection Issues**
   - Check connection pool: `intellicrack-debug db-pool`
   - Monitor slow queries
   - Verify network connectivity

### Debug Mode

```bash
# Enable debug logging
export INTELLICRACK_DEBUG=true
systemctl restart intellicrack

# View logs
journalctl -u intellicrack -f
```

## Maintenance

### Regular Tasks

Weekly:
- Review security logs
- Check disk usage
- Update virus definitions
- Test backups

Monthly:
- Security updates
- Performance review
- Certificate renewal check
- Capacity planning

### Upgrade Procedure

```bash
# Backup first
intellicrack-backup create

# Stop service
systemctl stop intellicrack

# Upgrade
apt update && apt upgrade intellicrack

# Run migrations
intellicrack-migrate upgrade head

# Start service
systemctl start intellicrack

# Verify
intellicrack-health-check
```
