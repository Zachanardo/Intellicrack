# AI Models Quick Reference

## Provider API Key Requirements

| Provider | API Key Required | Where to Get Key |
|----------|-----------------|------------------|
| OpenAI | ✅ Yes | https://platform.openai.com/api-keys |
| Anthropic | ✅ Yes | https://console.anthropic.com/settings/keys |
| Google Gemini | ✅ Yes | https://makersuite.google.com/app/apikey |
| Local (Ollama) | ❌ No | Install from https://ollama.ai |
| Azure OpenAI | ✅ Yes | Azure Portal - Your Deployment |
| AWS Bedrock | ✅ Yes | AWS Console - IAM Credentials |
| Cohere | ✅ Yes | https://dashboard.cohere.com/api-keys |
| Hugging Face | ⚠️ Optional | https://huggingface.co/settings/tokens |
| OpenRouter | ✅ Yes | https://openrouter.ai/keys |
| Together AI | ✅ Yes | https://api.together.xyz/settings/api-keys |
| Perplexity | ✅ Yes | https://www.perplexity.ai/settings/api |
| Groq | ✅ Yes | https://console.groq.com/keys |
| Replicate | ✅ Yes | https://replicate.com/account/api-tokens |
| DeepInfra | ✅ Yes | https://deepinfra.com/dash/api_keys |
| Anyscale | ✅ Yes | https://console.anyscale.com/credentials |
| LM Studio | ❌ No | Local application |

## Top Models by Use Case

### Best for Complex Analysis
- **OpenAI**: GPT-4o, GPT-4-turbo
- **Anthropic**: Claude 3.5 Sonnet, Claude 3 Opus
- **Google**: Gemini 1.5 Pro, Gemini 2.0 Flash

### Best for Speed
- **OpenAI**: GPT-3.5-turbo
- **Anthropic**: Claude 3.5 Haiku
- **Google**: Gemini 1.5 Flash
- **Groq**: Llama 3.3 70B (hardware accelerated)

### Best for Code Generation
- **OpenAI**: GPT-4o (best overall)
- **Anthropic**: Claude 3.5 Sonnet (excellent for refactoring)
- **Local**: Qwen 2.5 Coder, DeepSeek Coder

### Best for Privacy (Local)
- **Ollama**: Llama 3.3, Mistral, Phi-3
- **LM Studio**: Any GGUF model
- **Hugging Face**: Self-hosted models

## Model Selection Tips

### For Reverse Engineering:
1. **Binary Analysis**: Use GPT-4o or Claude 3.5 Sonnet
2. **Pattern Recognition**: Gemini 1.5 Pro with vision
3. **Exploit Development**: GPT-4-turbo with detailed prompts
4. **Quick Checks**: GPT-3.5-turbo or Claude Haiku

### For Performance:
- **Large Context**: Claude 3 (200k), Gemini 1.5 Pro (1M)
- **Fast Response**: Groq-hosted models, GPT-3.5-turbo
- **Batch Processing**: Local models with GPU
- **Real-time**: Gemini 1.5 Flash, Claude Haiku

### For Cost Efficiency:
- **Free Tier**: Gemini Flash (limited), Local models
- **Low Cost**: GPT-3.5-turbo, Claude Haiku
- **Best Value**: GPT-4o-mini, Gemini 1.5 Flash

## Auto-Refresh Feature

The AI Assistant automatically refreshes available models when:
- You enter/update an API key (1-second delay)
- You click "Refresh Models" button
- You switch providers

This ensures you always see the latest available models without manual intervention.

## Troubleshooting Quick Fixes

| Issue | Solution |
|-------|----------|
| Models not loading | Check API key and click "Refresh Models" |
| Rate limit errors | Wait 60 seconds or upgrade API plan |
| Network timeout | Check firewall/VPN settings |
| Model not found | Model may be renamed - refresh list |
| Slow responses | Try a faster model or check connection |

## Environment Variables (Optional)

For production use, set API keys as environment variables:
```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="AIza..."
```

Intellicrack will automatically detect and use these if no key is entered in the UI.
