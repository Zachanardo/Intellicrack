# Intellicrack LLM Model Formats - Complete User Guide

## Overview

Intellicrack supports multiple LLM (Large Language Model) formats and providers to enable flexible AI-powered binary analysis and script generation. This guide covers all supported model formats, their setup requirements, use cases, and configuration details.

---

## 🚀 Quick Start Summary

| Format | Best For | Difficulty | Speed | Memory Usage |
|--------|----------|------------|-------|--------------|
| **OpenAI** | API usage, fastest | Easy | Very Fast | Low |
| **Anthropic** | Claude models, reasoning | Easy | Very Fast | Low |
| **Local GGUF** | Offline, privacy | Medium | Fast | Medium |
| **Ollama** | Local ease-of-use | Easy | Fast | Medium |
| **PyTorch** | Custom models, research | Hard | Medium | High |
| **ONNX** | Cross-platform, optimized | Medium | Fast | Medium |
| **Safetensors** | Safe loading, modern | Medium | Fast | Medium |
| **GPTQ** | Quantized models | Hard | Fast | Low |
| **HuggingFace** | Model hub access | Medium | Medium | Medium |

---

## 1. OpenAI Backend

### Description
Connect to OpenAI's API for access to GPT-3.5, GPT-4, and other models.

### Setup Requirements
```bash
pip install openai>=1.0.0
```

### Configuration
- **API Key**: Required (get from OpenAI platform)
- **Model**: `gpt-3.5-turbo`, `gpt-4`, `gpt-4-turbo`, etc.
- **Base URL**: Optional custom endpoint

### Example Configuration
```json
{
  "provider": "openai",
  "model_name": "gpt-4-turbo",
  "api_key": "sk-...",
  "context_length": 128000,
  "temperature": 0.7,
  "max_tokens": 4096
}
```

### Use Cases
- **Script Generation**: Fast Frida/Ghidra script creation
- **Vulnerability Analysis**: Pattern recognition and exploit development
- **Code Analysis**: Understanding complex binary structures

### Pros
✅ Fastest response times
✅ State-of-the-art reasoning
✅ No local setup required
✅ Reliable uptime

### Cons
❌ Requires internet connection
❌ Usage costs
❌ Data sent to OpenAI servers

---

## 2. Anthropic Backend

### Description
Access Claude models for advanced reasoning and analysis tasks.

### Setup Requirements
```bash
pip install anthropic>=0.8.0
```

### Configuration
- **API Key**: Required (get from Anthropic Console)
- **Model**: `claude-3-sonnet`, `claude-3-opus`, `claude-3-haiku`
- **Base URL**: Optional custom endpoint

### Example Configuration
```json
{
  "provider": "anthropic",
  "model_name": "claude-3-sonnet-20240229",
  "api_key": "sk-ant-...",
  "context_length": 200000,
  "temperature": 0.7,
  "max_tokens": 4096
}
```

### Use Cases
- **Complex Analysis**: Multi-step binary analysis workflows
- **Research Tasks**: Academic-level reverse engineering explanations
- **Safety-Critical**: Responsible AI for security research

### Pros
✅ Excellent reasoning capabilities
✅ Large context windows
✅ Safety-focused responses
✅ Constitutional AI training

### Cons
❌ Requires internet connection
❌ Usage costs
❌ Slower than GPT models

---

## 3. Local GGUF Backend

### Description
Run quantized models locally using the GGUF format with llama.cpp.

### Setup Requirements
```bash
# Install llama-cpp-python
pip install llama-cpp-python

# GPU support (optional)
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python --force-reinstall --no-cache-dir
```

### Model Sources
- **Hugging Face**: Search for models with `.gguf` extension
- **Popular Models**:
  - `TheBloke/Llama-2-7B-Chat-GGUF`
  - `TheBloke/CodeLlama-7B-Instruct-GGUF`
  - `microsoft/DialoGPT-medium-GGUF`

### Example Configuration
```json
{
  "provider": "local_gguf",
  "model_name": "CodeLlama-7B-Q4_K_M.gguf",
  "model_path": "/models/CodeLlama-7B-Q4_K_M.gguf",
  "context_length": 4096,
  "temperature": 0.7,
  "n_gpu_layers": 35
}
```

### Use Cases
- **Offline Analysis**: No internet required
- **Privacy**: All data stays local
- **Cost-Effective**: No API fees
- **Custom Models**: Run specialized security models

### Pros
✅ Complete privacy
✅ No ongoing costs
✅ Works offline
✅ Good performance with GPU

### Cons
❌ Requires powerful hardware
❌ Initial setup complexity
❌ Model quality varies

---

## 4. Ollama Backend

### Description
Easy-to-use local model serving with automatic model management.

### Setup Requirements
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2:7b
ollama pull codellama:7b
```

### Available Models
```bash
ollama list  # Show installed models
ollama pull mistral:7b  # Install new model
```

### Example Configuration
```json
{
  "provider": "ollama",
  "model_name": "codellama:7b",
  "api_base": "http://localhost:11434",
  "context_length": 4096,
  "temperature": 0.7
}
```

### Use Cases
- **Development**: Easy local testing and development
- **Learning**: Understanding model behavior without complexity
- **Prototyping**: Quick AI feature implementation

### Pros
✅ Extremely easy setup
✅ Automatic model management
✅ Good performance
✅ Active community

### Cons
❌ Limited model selection
❌ Less control over inference
❌ Requires Ollama service running

---

## 5. PyTorch Backend

### Description
Load and run PyTorch models directly for maximum flexibility and customization.

### Setup Requirements
```bash
pip install torch>=2.0.0 transformers>=4.30.0 accelerate>=0.20.0 bitsandbytes>=0.39.0
```

### Model Sources
- **Hugging Face**: `transformers` compatible models
- **Custom Models**: Your own fine-tuned models
- **Research Models**: Experimental architectures

### Example Configuration
```json
{
  "provider": "pytorch",
  "model_name": "microsoft/DialoGPT-medium",
  "model_path": "/models/custom-security-model",
  "device": "cuda",
  "torch_dtype": "float16",
  "load_in_8bit": true,
  "trust_remote_code": false
}
```

### Advanced Features
- **Quantization**: 8-bit and 4-bit loading
- **LoRA Adapters**: Load fine-tuned adapters
- **Custom Tokenizers**: Specialized tokenization
- **Device Mapping**: Multi-GPU model sharding

### Use Cases
- **Research**: Custom model architectures
- **Fine-tuning**: Specialized security models
- **Experimentation**: Testing new techniques
- **Maximum Control**: Full access to model internals

### Pros
✅ Maximum flexibility
✅ Cutting-edge features
✅ Research capabilities
✅ Custom model support

### Cons
❌ Complex setup
❌ Requires deep ML knowledge
❌ High memory requirements
❌ Debugging complexity

---

## 6. TensorFlow Backend

### Description
Run TensorFlow/Keras models for AI-powered binary analysis.

### Setup Requirements
```bash
pip install tensorflow>=2.12.0 tensorflow-text>=2.12.0
```

### Model Sources
- **TensorFlow Hub**: Pre-trained models
- **Keras Applications**: Standard architectures
- **Custom Models**: TensorFlow SavedModel format

### Example Configuration
```json
{
  "provider": "tensorflow",
  "model_name": "tf-model-security",
  "model_path": "/models/security_classifier",
  "device": "/GPU:0",
  "optimize": true,
  "mixed_precision": true
}
```

### Use Cases
- **Legacy Models**: Existing TensorFlow infrastructure
- **Specialized Tasks**: Classification, embedding models
- **Production**: Stable, battle-tested framework

### Pros
✅ Mature ecosystem
✅ Production stability
✅ Good optimization tools
✅ Enterprise support

### Cons
❌ More verbose than PyTorch
❌ Limited transformer support
❌ Complex deployment

---

## 7. ONNX Backend

### Description
Cross-platform optimized models using the ONNX Runtime.

### Setup Requirements
```bash
pip install onnxruntime>=1.15.0 onnxruntime-gpu>=1.15.0  # GPU support
```

### Model Sources
- **ONNX Model Zoo**: Pre-converted models
- **Converted Models**: PyTorch/TF → ONNX
- **Optimized Models**: Hardware-specific optimizations

### Example Configuration
```json
{
  "provider": "onnx",
  "model_name": "security-analyzer-onnx",
  "model_path": "/models/security_model.onnx",
  "providers": ["CUDAExecutionProvider", "CPUExecutionProvider"],
  "optimize": true
}
```

### Use Cases
- **Cross-Platform**: Windows, Linux, macOS
- **Edge Deployment**: Embedded systems
- **Optimized Inference**: Maximum performance
- **Model Serving**: Production deployments

### Pros
✅ Excellent performance
✅ Cross-platform compatibility
✅ Hardware optimization
✅ Small memory footprint

### Cons
❌ Limited model selection
❌ Conversion complexity
❌ Debugging difficulties

---

## 8. Safetensors Backend

### Description
Safe and fast model loading using the Safetensors format.

### Setup Requirements
```bash
pip install safetensors>=0.3.0 transformers>=4.30.0
```

### Model Sources
- **Hugging Face**: Models with `.safetensors` files
- **Converted Models**: PyTorch → Safetensors
- **Security Models**: Verified model weights

### Example Configuration
```json
{
  "provider": "safetensors",
  "model_name": "security-model-safe",
  "model_path": "/models/model.safetensors",
  "config_path": "/models/config.json",
  "device": "cuda",
  "strict": true
}
```

### Use Cases
- **Security**: Verified model integrity
- **Fast Loading**: Optimized file format
- **Memory Mapping**: Efficient large model loading
- **Safe Deployment**: Protection against malicious models

### Pros
✅ Fastest loading times
✅ Memory efficient
✅ Security guarantees
✅ Growing adoption

### Cons
❌ Limited model availability
❌ Newer format
❌ Requires conversion for old models

---

## 9. GPTQ Backend

### Description
4-bit quantized models for efficient inference with minimal quality loss.

### Setup Requirements
```bash
pip install auto-gptq>=0.4.0 optimum>=1.13.0
```

### Model Sources
- **TheBloke**: Extensive GPTQ model collection
- **Hugging Face**: Search for `-GPTQ` models
- **Custom**: Quantize your own models

### Example Configuration
```json
{
  "provider": "gptq",
  "model_name": "TheBloke/Llama-2-7B-Chat-GPTQ",
  "model_path": "/models/llama-2-7b-gptq",
  "device": "cuda",
  "use_triton": true,
  "group_size": 128
}
```

### Use Cases
- **Memory Constrained**: Limited GPU VRAM
- **Fast Inference**: Reduced computation
- **Cost Effective**: Lower hardware requirements
- **Edge Deployment**: Mobile/embedded systems

### Pros
✅ 4x memory reduction
✅ Faster inference
✅ Maintains quality
✅ GPU optimized

### Cons
❌ CUDA only
❌ Complex setup
❌ Model compatibility issues

---

## 10. HuggingFace Local Backend

### Description
Local execution of HuggingFace models with full transformers integration.

### Setup Requirements
```bash
pip install transformers>=4.30.0 torch>=2.0.0 accelerate>=0.20.0
```

### Model Sources
- **Model Hub**: 150,000+ models
- **Organizations**: Microsoft, Google, Meta models
- **Community**: Open source contributions

### Example Configuration
```json
{
  "provider": "huggingface_local",
  "model_name": "microsoft/CodeBERT-base",
  "cache_dir": "/models/hf_cache",
  "device_map": "auto",
  "torch_dtype": "float16",
  "low_cpu_mem_usage": true
}
```

### Use Cases
- **Code Analysis**: CodeBERT, GraphCodeBERT
- **Text Classification**: Security pattern detection
- **Embeddings**: Semantic similarity analysis
- **Research**: Latest model architectures

### Pros
✅ Largest model selection
✅ Easy integration
✅ Community support
✅ Regular updates

### Cons
❌ Variable quality
❌ Large downloads
❌ Dependency complexity

---

## 🛠️ Configuration Guide

### Setting Up Models in Intellicrack

1. **Open LLM Configuration**
   - Tools → LLM Configuration
   - Or click the AI icon in toolbar

2. **Select Provider Tab**
   - Choose your desired model format
   - Each tab provides format-specific options

3. **Configure Model**
   - Enter model details
   - Set paths for local models
   - Configure performance settings

4. **Test Configuration**
   - Use "Test Connection" button
   - Verify model loads correctly
   - Check response quality

### Model Performance Profiles

#### **Speed Optimized**
```json
{
  "temperature": 0.3,
  "max_tokens": 1024,
  "top_p": 0.9,
  "context_length": 2048
}
```

#### **Quality Optimized**
```json
{
  "temperature": 0.7,
  "max_tokens": 4096,
  "top_p": 0.95,
  "context_length": 8192
}
```

#### **Research Mode**
```json
{
  "temperature": 0.8,
  "max_tokens": 8192,
  "top_p": 1.0,
  "context_length": 32768
}
```

---

## 🔧 Troubleshooting

### Common Issues

#### **CUDA Out of Memory**
```bash
# Solutions:
1. Reduce context_length
2. Enable load_in_8bit or load_in_4bit
3. Use device_map="auto"
4. Reduce batch_size
```

#### **Model Not Found**
```bash
# Check paths:
ls -la /path/to/model/
# Verify permissions:
chmod +r /path/to/model/*
```

#### **Slow Performance**
```bash
# Enable optimizations:
1. Use GPU acceleration
2. Enable mixed precision
3. Reduce context length
4. Use quantized models
```

#### **Import Errors**
```bash
# Update dependencies:
pip install --upgrade transformers torch accelerate
# Check CUDA compatibility:
python -c "import torch; print(torch.cuda.is_available())"
```

---

## 📊 Performance Comparison

| Model Type | Memory (GB) | Speed (tokens/s) | Quality | Setup |
|------------|-------------|------------------|---------|-------|
| OpenAI API | 0.1 | 50-100 | ★★★★★ | ⭐ |
| Anthropic | 0.1 | 30-60 | ★★★★★ | ⭐ |
| Local GGUF | 4-16 | 20-50 | ★★★★ | ⭐⭐⭐ |
| Ollama | 4-16 | 15-40 | ★★★★ | ⭐⭐ |
| PyTorch | 8-32 | 10-30 | ★★★★★ | ⭐⭐⭐⭐⭐ |
| ONNX | 4-16 | 25-60 | ★★★★ | ⭐⭐⭐ |
| Safetensors | 8-32 | 15-35 | ★★★★ | ⭐⭐⭐ |
| GPTQ | 2-8 | 30-70 | ★★★★ | ⭐⭐⭐⭐ |

---

## 🎯 Recommendations by Use Case

### **Beginner Users**
- Start with **OpenAI** or **Anthropic** APIs
- Move to **Ollama** for local experimentation
- Simple setup, immediate results

### **Privacy-Focused**
- Use **Local GGUF** with llama.cpp
- **Ollama** for ease of use
- All processing stays on your machine

### **Performance Critical**
- **GPTQ** models for speed + efficiency
- **ONNX** for optimized inference
- **API providers** for fastest response

### **Research & Development**
- **PyTorch** backend for flexibility
- **HuggingFace Local** for model variety
- Custom model training capabilities

### **Production Deployment**
- **ONNX** for cross-platform
- **Safetensors** for security
- **API providers** for reliability

---

## 📚 Further Reading

- [HuggingFace Transformers Documentation](https://huggingface.co/docs/transformers)
- [ONNX Runtime Performance Tuning](https://onnxruntime.ai/docs/performance/)
- [GPTQ Quantization Guide](https://github.com/IST-DASLab/gptq)
- [Safetensors Format Specification](https://github.com/huggingface/safetensors)

---

*This documentation is part of the Intellicrack project and is updated regularly to reflect new model formats and capabilities.*
