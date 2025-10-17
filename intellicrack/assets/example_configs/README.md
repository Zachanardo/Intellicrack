# Example Model Configurations

This directory contains ready-to-use model configuration files for Intellicrack's LLM system.

## Usage

These JSON files serve as reference configurations for setting up LLM models in Intellicrack. To use them:

1. **Manual Configuration**: Open the LLM Configuration dialog and manually enter settings based on these examples
2. **API Keys**: Copy the structure and replace `YOUR_API_KEY` placeholders with actual keys
3. **Model Paths**: For local models, update `model_path` to point to your local model files
4. **Customize**: Adjust parameters like `temperature`, `max_tokens`, and other settings as needed
5. **Save**: Save your customized configuration through the dialog

## Available Configurations

### API-Based Models

- `openai_gpt4.json` - OpenAI GPT-4 for fast, reliable analysis
- `anthropic_claude3.json` - Claude-3 for advanced reasoning
- `frida_specialized.json` - Optimized for Frida script generation
- `vulnerability_assessment.json` - Specialized for security analysis

### Local Models

- `ollama_codellama.json` - Easy local setup with Ollama
- `local_gguf_high_performance.json` - High-performance local inference
- `gptq_fast_inference.json` - Quantized models for limited GPU memory
- `pytorch_research.json` - Research and custom model setup
- `onnx_production.json` - Production-optimized inference

## Setup Requirements

### API Models

1. Obtain API keys from the respective providers
2. Replace `YOUR_API_KEY` placeholders with actual keys
3. Test the configuration

### Local Models

1. Download the specified model files
2. Update `model_path` to point to your local model files
3. Ensure required dependencies are installed
4. Adjust hardware-specific parameters

## Customization Tips

- **API Keys**: Store in environment variables for security
- **Model Paths**: Use absolute paths for reliability
- **Memory Settings**: Adjust based on your hardware capabilities
- **Temperature**: Lower for deterministic output, higher for creativity
- **Context Length**: Increase for longer analysis, decrease for speed

## Performance Tuning

### For Speed

- Reduce `context_length` and `max_tokens`
- Lower `temperature` to 0.1-0.3
- Use quantized models (GPTQ, GGUF Q4)

### For Quality

- Increase `context_length` and `max_tokens`
- Use higher-quality models (GPT-4, Claude-3 Opus)
- Adjust `temperature` to 0.6-0.8

### For Privacy

- Use local models only (GGUF, PyTorch, ONNX)
- Avoid API-based configurations
- Check model licenses and data usage policies

## Troubleshooting

### Common Issues

1. **API Key Errors**: Verify keys are correct and have sufficient credits
2. **Model Not Found**: Check local model paths and file permissions
3. **CUDA Errors**: Adjust GPU memory settings or use CPU fallback
4. **Import Errors**: Ensure all required dependencies are installed
