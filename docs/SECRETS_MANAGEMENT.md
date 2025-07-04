# Intellicrack Secrets Management

## Overview

Intellicrack uses a centralized secrets management system to securely handle API keys, tokens, and other sensitive information. The system supports multiple storage backends and provides a unified interface for accessing secrets.

## Features

- **Multiple Storage Backends**:
  - Environment variables (.env files)
  - OS keychain (Windows Credential Manager, macOS Keychain, Linux Secret Service)
  - Encrypted file storage with PBKDF2 key derivation
  
- **Security Features**:
  - Automatic encryption for file-based storage
  - OS keychain integration for secure storage
  - No plain text secrets in configuration files
  - Key rotation support

- **Developer Friendly**:
  - Simple API for getting/setting secrets
  - Automatic fallback mechanisms
  - Migration tools for existing configurations

## Quick Start

### 1. Create Your Local Environment File

Copy the example environment file:
```bash
cp .env.example .env.local
```

Edit `.env.local` and add your API keys:
```bash
# LLM API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
```

**Important**: Never commit `.env.local` or any file with real API keys to version control!

### 2. Using Secrets in Code

Instead of using `os.getenv()` directly, use the secrets manager:

```python
from intellicrack.utils.secrets_manager import get_secret, get_api_key

# Get a specific secret
api_key = get_secret('OPENAI_API_KEY')

# Get API key by service name
api_key = get_api_key('openai')  # Same as above

# Set a secret programmatically
from intellicrack.utils.secrets_manager import set_secret
set_secret('MY_API_KEY', 'secret-value-here')
```

### 3. Migrate Existing Configurations

Run the migration script to move existing API keys to secure storage:

```bash
python scripts/migrate_secrets.py
```

## Storage Hierarchy

The secrets manager checks for secrets in this order:

1. **Environment Variables** - Highest priority
2. **OS Keychain** - Secure system storage
3. **Encrypted File** - Local encrypted cache
4. **Default Value** - Fallback if not found

## Supported Secrets

### LLM API Keys
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GOOGLE_API_KEY`
- `COHERE_API_KEY`
- `HUGGINGFACE_API_TOKEN`
- `GROQ_API_KEY`
- `TOGETHER_API_KEY`

### Security Analysis Services
- `VIRUSTOTAL_API_KEY`
- `HYBRID_ANALYSIS_API_KEY`
- `MALWARE_BAZAAR_API_KEY`

### Cloud Services
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AZURE_API_KEY`
- `GCP_API_KEY`

### Application Secrets
- `JWT_SECRET_KEY`
- `ENCRYPTION_KEY`
- `SESSION_SECRET`
- `INTELLICRACK_REMOTE_SECRET`

### Generic
- `API_KEY`
- `SECRET_KEY`
- `DATABASE_URL`

## API Reference

### Getting Secrets

```python
# Get a secret with optional default
value = get_secret('SECRET_NAME', default='default-value')

# Get API key for a service
api_key = get_api_key('openai')  # Maps to OPENAI_API_KEY
```

### Setting Secrets

```python
# Set a secret (stored in keychain if available)
set_secret('SECRET_NAME', 'secret-value')

# Set without keychain (encrypted file only)
set_secret('SECRET_NAME', 'secret-value', use_keychain=False)
```

### Managing Secrets

```python
from intellicrack.utils.secrets_manager import get_secrets_manager

manager = get_secrets_manager()

# List all available secret keys
keys = manager.list_keys()

# Delete a secret
manager.delete('SECRET_NAME')

# Export secrets (values redacted by default)
config = manager.export_secrets()

# Export with values (dangerous!)
config = manager.export_secrets(include_values=True)

# Import secrets
manager.import_secrets({'API_KEY': 'new-value'})

# Rotate a key
manager.rotate_key('OLD_KEY_NAME', 'NEW_KEY_NAME')
```

## Security Best Practices

1. **Never hardcode secrets** in your source code
2. **Use .env.local** for personal development secrets
3. **Use .env.example** as a template (no real values)
4. **Ensure .env files** are in .gitignore
5. **Use unique secrets** for each environment
6. **Rotate secrets regularly**
7. **Use OS keychain** when available for best security

## File Locations

- **Config Directory**:
  - Windows: `%APPDATA%\intellicrack\secrets\`
  - macOS: `~/Library/Application Support/intellicrack/secrets/`
  - Linux: `~/.config/intellicrack/secrets/`

- **Files**:
  - `secrets.enc` - Encrypted secrets storage
  - `.key` - Encryption key (restricted permissions)

## Troubleshooting

### "API key not found" Error
1. Check if the key is set in `.env.local`
2. Ensure the file is in the project root
3. Try running the migration script
4. Check environment variable is exported

### Keychain Access Issues
- On macOS: Grant Terminal/IDE keychain access
- On Linux: Ensure secret service is running
- On Windows: Check Windows Credential Manager

### Migration Issues
- Backup your configuration files first
- Check file permissions
- Run with appropriate privileges

## Development

### Adding New Secret Types

1. Add to `KNOWN_SECRETS` in `secrets_manager.py`
2. Update `.env.example` with the new key
3. Document in this file
4. Update migration script if needed

### Testing

```python
# Test secret storage
python -c "from intellicrack.utils.secrets_manager import set_secret, get_secret; set_secret('TEST_KEY', 'test-value'); print(get_secret('TEST_KEY'))"
```

## Migration from Old System

The old system stored API keys in:
- `~/.intellicrack/llm_configs/models.json` (plain text)
- Various config files with embedded keys

The new system:
- Centralizes all secrets
- Encrypts file storage
- Uses OS keychains when available
- Maintains backward compatibility

Run `python scripts/migrate_secrets.py` to automatically migrate.