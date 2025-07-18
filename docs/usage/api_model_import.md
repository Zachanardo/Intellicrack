# API Model Import Feature

This document describes the design and usage of the API Model Import feature in Intellicrack.

## Overview

The API Model Import feature allows users to import AI models from both local files and external API repositories. This provides flexibility in how models are acquired and managed within Intellicrack.

## Architecture

The feature is implemented using a modular, extensible architecture:

```
                  +-------------------+
                  |   ModelManager    |
                  +--------+----------+
                           |
                           | (manages)
                           v
       +-------------------+--------------------+
       |                   |                    |
+------+------+    +-------+-------+    +-------+-------+
| Repository 1 |    | Repository 2  |    | Repository 3  |
| (Local File) |    | (e.g., OpenAI)|    | (Other API)   |
+------+------+    +-------+-------+    +-------+-------+
       |                   |                    |
       v                   v                    v
  Local Files         API Source 1         API Source 2
```

### Key Components

1. **ModelRepositoryInterface**: Base interface for all model repositories
2. **LocalFileRepository**: Repository implementation for local file system
3. **APIRepositoryBase**: Base class for API-based repositories
4. **OpenAIRepository**: Example implementation for OpenAI's API
5. **RepositoryFactory**: Factory for creating repository instances
6. **ModelManager**: Central manager for coordinating repositories

## Usage

### Importing Models

Users can import models in two ways:

1. **Import from File**: 
   - Click "Import Custom Model" in the Settings tab
   - Select "Import from File"
   - Choose a GGUF model file
   - The model will be imported and registered with the local repository

2. **Import from API Repository**:
   - Click "Import Custom Model" in the Settings tab
   - Select "Import from API Repository"
   - Choose a repository and model
   - Click "Download & Import"
   - The model will be downloaded, saved locally, and registered

### Configuring API Repositories

1. Go to the Settings tab
2. Click "Configure API Model Repositories"
3. For each repository tab:
   - Enable/disable the repository
   - Enter the API key
   - Configure endpoint, timeout, and other settings
   - Set rate limits
   - Test the connection
4. Configure global cache settings
5. Click "Save Configuration"

## Adding New API Repositories

To add a new API repository type:

1. Create a new class that inherits from `APIRepositoryBase`
2. Implement the required methods:
   - `get_available_models()`
   - `get_model_details(model_id)`
   - `authenticate()`
3. Register the repository type in `models/repositories/__init__.py`:
   ```python
   RepositoryFactory.register_repository_type("your_repo_name", YourRepositoryClass)
   ```
4. Add the default configuration in `load_config()`:
   ```python
   "your_repo_name": {
       "type": "your_repo_name",
       "enabled": False,
       "api_key": "",
       "endpoint": "https://api.example.com",
       "timeout": 60,
       ...
   }
   ```

## Available Repositories

The system includes the following API repositories:

1. **Local File Repository**
   - Type: `local`
   - Description: Manages locally stored model files
   - Features: File scanning, metadata extraction, integrity verification

2. **OpenAI Repository**
   - Type: `openai`
   - Description: Access to OpenAI models via their API
   - API Endpoint: https://api.openai.com/v1
   - Models: GPT-4, GPT-3.5-Turbo, etc.

3. **Anthropic Repository**
   - Type: `anthropic`
   - Description: Access to Anthropic's Claude models via their API
   - API Endpoint: https://api.anthropic.com
   - Models: Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku, etc.

4. **OpenRouter Repository**
   - Type: `openrouter`
   - Description: Unified API access to multiple LLM providers
   - API Endpoint: https://openrouter.ai/api
   - Models: Various models from different providers

5. **Google Repository**
   - Type: `google`
   - Description: Access to Google's Gemini models via their GenerativeAI API
   - API Endpoint: https://generativelanguage.googleapis.com
   - Models: Gemini Pro, Gemini Ultra, etc.

6. **LMStudio Repository**
   - Type: `lmstudio`
   - Description: Access to locally hosted LMStudio server
   - API Endpoint: http://localhost:1234/v1 (default)
   - Models: Any model loaded in LMStudio

## Repository Configuration

Each repository supports the following configuration options:

- `type`: Repository type identifier
- `enabled`: Whether the repository is enabled
- `api_key`: API key for authentication
- `endpoint`: Base URL for the API
- `timeout`: Request timeout in seconds
- `proxy`: Optional proxy URL
- `rate_limit`: Rate limiting settings:
  - `requests_per_minute`: Maximum requests per minute
  - `requests_per_day`: Maximum requests per day

## Cache Configuration

API responses can be cached to improve performance and reduce API usage:

- `enabled`: Whether caching is enabled
- `ttl`: Time-to-live for cached items in seconds
- `max_size_mb`: Maximum cache size in megabytes

## Implementation Details

### Model Information

Models are represented by the `ModelInfo` class, which contains:

- Basic metadata: ID, name, description, version
- Technical details: size, format, parameters, context length
- Status information: download URL, local path, checksum

### Progress Tracking

Long-running operations like downloads support progress tracking:

- Progress is displayed in the UI with a progress bar
- Status messages are updated during the operation
- Completion callbacks handle success/failure states

### Error Handling

The system includes comprehensive error handling:

- API errors are logged and reported to the user
- Download failures are detected and reported
- Checksum verification ensures file integrity
- Rate limiting prevents API abuse