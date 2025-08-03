# Example Model Configurations

This directory contains ready-to-use model configuration files for Intellicrack's LLM system.

## Usage

1. **Import Configuration**: Use the "Import Configuration" button in the LLM Configuration dialog
2. **Load from File**: Select any `.json` file from this directory
3. **Customize**: Edit the configuration to match your API keys and local paths
4. **Save**: Save your customized configuration for future use

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

### Getting Help
- Check the main documentation in `/dev/LLM_MODEL_FORMATS_USER_GUIDE.md`
- Review hardware requirements for each model type
- Test with simpler configurations first before using complex setups
