# AI Assistant User Guide

## Overview

The AI Assistant tab in Intellicrack provides comprehensive AI-powered analysis, code generation, and intelligent assistance for reverse engineering and exploitation tasks. This guide covers the enhanced model selection features and dynamic model fetching capabilities.

## Supported AI Providers

Intellicrack now supports 16 different AI providers, giving you access to a wide range of language models:

### Major Providers
- **OpenAI** - GPT-4o, GPT-4 Turbo, GPT-3.5 Turbo, and more
- **Anthropic** - Claude 3.5 Sonnet, Claude 3.5 Haiku, Claude 3 Opus
- **Google Gemini** - Gemini 2.0 Flash, Gemini 1.5 Pro/Flash
- **Local (Ollama)** - Run models locally without API keys

### Cloud Platforms
- **Azure OpenAI** - Microsoft's enterprise OpenAI deployments
- **AWS Bedrock** - Amazon's managed AI service
- **Google Vertex AI** - Enterprise Google AI platform

### Alternative Providers
- **Cohere** - Command R+, Command R, and embedding models
- **Hugging Face** - Access to thousands of open-source models
- **OpenRouter** - Unified API for multiple providers
- **Together AI** - Fast inference for open models
- **Perplexity** - Specialized search-enhanced models
- **Groq** - Ultra-fast inference hardware
- **Replicate** - Easy deployment of ML models
- **DeepInfra** - Serverless AI infrastructure
- **Anyscale** - Scalable AI compute
- **LM Studio** - Local model management

## Model Selection Features

### Dynamic Model Fetching

The AI Assistant now features dynamic model fetching, which automatically retrieves the latest available models from each provider when you supply an API key.

#### How It Works:
1. Select your preferred provider from the dropdown
2. Enter your API key in the designated field
3. Models will automatically refresh after 1 second
4. The dropdown will populate with all available models

#### Manual Refresh:
- Click the **"Refresh Models"** button next to the API key field to manually update the model list
- Useful when switching between accounts or after adding new models

### Auto-Refresh Feature

The model list automatically refreshes when:
- You enter or update an API key (with a 1-second delay to avoid excessive API calls)
- You switch between providers
- You click the manual refresh button

### Fallback Model Lists

If dynamic fetching fails (no API key, network issues, or API errors), Intellicrack provides comprehensive fallback lists with the latest models:

#### OpenAI Models Include:
- GPT-4o variants (latest, 2024-11-20, 2024-08-06, mini)
- GPT-4 Turbo (latest, preview versions)
- GPT-4 (standard, 32k context)
- GPT-3.5 Turbo (all variants)
- Embedding models (text-embedding-3-large/small, ada-002)
- Specialized models (DALL-E 3, Whisper, TTS)

#### Anthropic Models Include:
- Claude 3.5 Sonnet (20241022, 20240620)
- Claude 3.5 Haiku (20241022)
- Claude 3 Opus, Sonnet, Haiku
- Claude 2.1, 2.0
- Claude Instant 1.2

#### Google Gemini Models Include:
- Gemini 2.0 Flash (experimental, thinking)
- Gemini 1.5 Pro/Flash (latest, 002 versions)
- Gemini 1.0 Pro
- Legacy Gemini Pro/Vision
- Embedding models

## API Key Requirements

### Providers Requiring API Keys:
- OpenAI, Anthropic, Google Gemini
- Azure OpenAI, AWS Bedrock
- Cohere, Perplexity, Together AI
- Most commercial providers

### Providers Without API Key Requirements:
- Local (Ollama) - Runs on your machine
- LM Studio - Local model management

### API Key Security:
- Keys are only stored in memory during your session
- Keys are never logged or saved to disk
- Keys are used only for model listing and inference
- Consider using environment variables for production use

## Using the AI Assistant

### Quick Start:
1. Navigate to the **AI Assistant** tab
2. Select your provider from the dropdown
3. Enter your API key (if required)
4. Wait for models to load or click "Refresh Models"
5. Select your preferred model
6. Configure temperature and max tokens
7. Start using AI-powered features

### Model Configuration:
- **Temperature**: Controls randomness (0.0 = deterministic, 1.0 = creative)
- **Max Tokens**: Maximum response length
- **API Endpoint**: Custom endpoints for self-hosted models

### Tips for Best Results:
- Use GPT-4o or Claude 3.5 Sonnet for complex analysis
- Use faster models (GPT-3.5, Claude Haiku) for quick tasks
- Local models (Ollama) are great for privacy-sensitive work
- Specialized models may perform better for specific tasks

## Troubleshooting

### Models Not Loading:
1. Check your API key is correct
2. Verify internet connectivity
3. Check provider service status
4. Try the manual refresh button
5. Check the console for error messages

### API Errors:
- **Rate Limits**: Wait and retry, or upgrade your plan
- **Invalid Key**: Double-check your API key
- **Network Error**: Check firewall/proxy settings
- **Model Not Found**: Model may be deprecated or renamed

### Performance Tips:
- Close unnecessary browser tabs to free memory
- Use appropriate model sizes for your hardware
- Consider local models for large-scale processing
- Enable GPU acceleration if available

## Advanced Features

### Multi-Provider Workflow:
You can switch between providers during your session to leverage different models' strengths:
- Use GPT-4o for initial analysis
- Switch to Claude for detailed code review
- Use local models for bulk processing

### Custom Deployments:
For Azure OpenAI and other enterprise deployments:
- Use your deployment name instead of model name
- Configure custom endpoints in settings
- Set organization-specific parameters

### Batch Processing:
The AI Assistant supports batch operations:
- Queue multiple analyses
- Process results asynchronously
- Export results in various formats

## Updates and Maintenance

The model lists are regularly updated to include:
- New model releases
- Deprecated model removal
- Performance improvements
- Bug fixes

To ensure you have the latest features:
- Keep Intellicrack updated
- Check provider documentation for new models
- Report issues on the GitHub repository

---

For more information on specific AI features and capabilities, see the [AI Script Generation](../FRIDA_INTEGRATION_GUIDE.md) and [Advanced Analysis](../api_reference.md) documentation.
