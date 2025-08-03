# Example Model Configurations for Intellicrack

This document provides ready-to-use model configurations for various use cases in Intellicrack. Copy and paste these configurations into the LLM Configuration dialog or save them as JSON files.

---

## 🚀 Quick Setup Configurations

### 1. OpenAI GPT-4 (Recommended for Beginners)

**Use Case**: Fast, reliable script generation and analysis

```json
{
  "provider": "openai",
  "model_name": "gpt-4-turbo",
  "api_key": "YOUR_OPENAI_API_KEY",
  "context_length": 128000,
  "temperature": 0.7,
  "max_tokens": 4096,
  "tools_enabled": true,
  "custom_params": {
    "top_p": 0.95,
    "frequency_penalty": 0.0,
    "presence_penalty": 0.0
  }
}
```

**Setup Steps**:
1. Get API key from https://platform.openai.com/
2. Replace `YOUR_OPENAI_API_KEY` with actual key
3. Test with simple script generation

---

### 2. Anthropic Claude-3 (Best for Complex Analysis)

**Use Case**: Advanced reasoning, research-grade analysis

```json
{
  "provider": "anthropic",
  "model_name": "claude-3-sonnet-20240229",
  "api_key": "YOUR_ANTHROPIC_API_KEY",
  "context_length": 200000,
  "temperature": 0.7,
  "max_tokens": 4096,
  "tools_enabled": true,
  "custom_params": {
    "top_p": 0.9,
    "top_k": 40
  }
}
```

**Setup Steps**:
1. Get API key from https://console.anthropic.com/
2. Replace `YOUR_ANTHROPIC_API_KEY` with actual key
3. Ideal for multi-step vulnerability analysis

---

## 🏠 Local Model Configurations

### 3. Ollama CodeLlama (Easy Local Setup)

**Use Case**: Local code analysis, privacy-focused

```json
{
  "provider": "ollama",
  "model_name": "codellama:7b-instruct",
  "api_base": "http://localhost:11434",
  "context_length": 4096,
  "temperature": 0.3,
  "max_tokens": 2048,
  "tools_enabled": true,
  "custom_params": {
    "top_p": 0.9,
    "repeat_penalty": 1.1,
    "num_predict": 2048
  }
}
```

**Setup Steps**:
```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the model
ollama pull codellama:7b-instruct

# Start Ollama service
ollama serve
```

---

### 4. Local GGUF High Performance

**Use Case**: Maximum local performance with GPU acceleration

```json
{
  "provider": "local_gguf",
  "model_name": "CodeLlama-7B-Instruct-Q4_K_M.gguf",
  "model_path": "/models/CodeLlama-7B-Instruct-Q4_K_M.gguf",
  "context_length": 8192,
  "temperature": 0.4,
  "max_tokens": 4096,
  "tools_enabled": true,
  "custom_params": {
    "n_gpu_layers": 35,
    "n_ctx": 8192,
    "n_batch": 512,
    "n_threads": 8,
    "rope_freq_base": 10000.0,
    "rope_freq_scale": 1.0
  }
}
```

**Setup Steps**:
```bash
# Install llama-cpp-python with GPU support
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python --force-reinstall

# Download model
wget https://huggingface.co/TheBloke/CodeLlama-7B-Instruct-GGUF/resolve/main/codellama-7b-instruct.Q4_K_M.gguf
```

---

## 🎯 Specialized Configurations

### 5. Security Research (PyTorch + Quantization)

**Use Case**: Custom security models, research applications

```json
{
  "provider": "pytorch",
  "model_name": "microsoft/DialoGPT-medium",
  "model_path": "/models/security-tuned-model",
  "context_length": 4096,
  "temperature": 0.6,
  "max_tokens": 2048,
  "tools_enabled": true,
  "custom_params": {
    "device": "cuda",
    "torch_dtype": "float16",
    "load_in_8bit": true,
    "trust_remote_code": false,
    "use_cache": true,
    "pad_token_id": 50256,
    "do_sample": true,
    "top_p": 0.92,
    "repetition_penalty": 1.1
  }
}
```

**Use Cases**:
- Custom fine-tuned security models
- Research with specific model architectures
- Maximum control over inference parameters

---

### 6. Fast Binary Analysis (GPTQ Quantized)

**Use Case**: Fast inference on limited GPU memory

```json
{
  "provider": "gptq",
  "model_name": "TheBloke/Llama-2-7B-Chat-GPTQ",
  "model_path": "/models/Llama-2-7B-Chat-GPTQ",
  "context_length": 4096,
  "temperature": 0.5,
  "max_tokens": 2048,
  "tools_enabled": true,
  "custom_params": {
    "device": "cuda",
    "use_triton": true,
    "group_size": 128,
    "desc_act": false,
    "bits": 4,
    "max_memory": {"0": "6GB"}
  }
}
```

**Benefits**:
- 4x memory reduction
- Faster inference
- Fits on smaller GPUs (6GB+)

---

### 7. Cross-Platform ONNX

**Use Case**: Optimized inference, production deployment

```json
{
  "provider": "onnx",
  "model_name": "security-analyzer-onnx",
  "model_path": "/models/security_model.onnx",
  "context_length": 2048,
  "temperature": 0.4,
  "max_tokens": 1024,
  "tools_enabled": true,
  "custom_params": {
    "providers": [
      "CUDAExecutionProvider",
      "CPUExecutionProvider"
    ],
    "provider_options": {
      "CUDAExecutionProvider": {
        "device_id": 0,
        "arena_extend_strategy": "kNextPowerOfTwo"
      }
    },
    "optimize": true,
    "graph_optimization_level": "all"
  }
}
```

**Ideal For**:
- Production deployments
- Cross-platform compatibility
- Maximum inference speed

---

## 📊 Performance Profiles

### Speed Optimized Profile

```json
{
  "context_length": 2048,
  "temperature": 0.3,
  "max_tokens": 1024,
  "custom_params": {
    "top_p": 0.9,
    "top_k": 40,
    "repetition_penalty": 1.05,
    "do_sample": true
  }
}
```

### Quality Optimized Profile

```json
{
  "context_length": 8192,
  "temperature": 0.7,
  "max_tokens": 4096,
  "custom_params": {
    "top_p": 0.95,
    "top_k": 50,
    "repetition_penalty": 1.1,
    "do_sample": true
  }
}
```

### Research Profile

```json
{
  "context_length": 16384,
  "temperature": 0.8,
  "max_tokens": 8192,
  "custom_params": {
    "top_p": 1.0,
    "top_k": 0,
    "repetition_penalty": 1.0,
    "do_sample": true
  }
}
```

---

## 🎮 Use Case Specific Configurations

### Frida Script Generation

```json
{
  "provider": "openai",
  "model_name": "gpt-4-turbo",
  "context_length": 16384,
  "temperature": 0.4,
  "max_tokens": 2048,
  "custom_params": {
    "system_prompt": "You are a Frida scripting expert. Generate precise, working Frida scripts for binary analysis and hooking.",
    "top_p": 0.9,
    "frequency_penalty": 0.1
  }
}
```

### Ghidra Analysis

```json
{
  "provider": "anthropic",
  "model_name": "claude-3-sonnet-20240229",
  "context_length": 32768,
  "temperature": 0.6,
  "max_tokens": 4096,
  "custom_params": {
    "system_prompt": "You are a Ghidra reverse engineering expert. Analyze binary structures and provide detailed explanations.",
    "top_p": 0.95
  }
}
```

### Vulnerability Assessment

```json
{
  "provider": "anthropic",
  "model_name": "claude-3-opus-20240229",
  "context_length": 200000,
  "temperature": 0.7,
  "max_tokens": 8192,
  "custom_params": {
    "system_prompt": "You are a cybersecurity expert specializing in vulnerability assessment and exploit development.",
    "top_p": 0.9
  }
}
```

---

## 🔧 Hardware-Specific Configurations

### High-End GPU (RTX 4090, 24GB VRAM)

```json
{
  "provider": "pytorch",
  "model_name": "codellama/CodeLlama-13b-Instruct-hf",
  "context_length": 16384,
  "temperature": 0.5,
  "max_tokens": 4096,
  "custom_params": {
    "device": "cuda",
    "torch_dtype": "float16",
    "load_in_8bit": false,
    "max_memory": {"0": "22GB"},
    "device_map": "auto"
  }
}
```

### Mid-Range GPU (RTX 3070, 8GB VRAM)

```json
{
  "provider": "gptq",
  "model_name": "TheBloke/CodeLlama-7B-Instruct-GPTQ",
  "context_length": 8192,
  "temperature": 0.5,
  "max_tokens": 2048,
  "custom_params": {
    "device": "cuda",
    "use_triton": true,
    "max_memory": {"0": "7GB"},
    "group_size": 128
  }
}
```

### CPU Only (No GPU)

```json
{
  "provider": "local_gguf",
  "model_name": "CodeLlama-7B-Instruct-Q4_K_M.gguf",
  "context_length": 4096,
  "temperature": 0.5,
  "max_tokens": 2048,
  "custom_params": {
    "n_gpu_layers": 0,
    "n_threads": 16,
    "n_batch": 256,
    "use_mlock": true
  }
}
```

---

## 📱 Mobile/Edge Configurations

### Lightweight ONNX Model

```json
{
  "provider": "onnx",
  "model_name": "distilbert-base-uncased",
  "model_path": "/models/distilbert.onnx",
  "context_length": 512,
  "temperature": 0.4,
  "max_tokens": 256,
  "custom_params": {
    "providers": ["CPUExecutionProvider"],
    "optimize": true,
    "enable_profiling": false
  }
}
```

### Quantized Mobile Model

```json
{
  "provider": "local_gguf",
  "model_name": "TinyLlama-1.1B-Chat-v1.0.Q4_K_M.gguf",
  "model_path": "/models/tinyllama-1.1b-q4.gguf",
  "context_length": 2048,
  "temperature": 0.6,
  "max_tokens": 512,
  "custom_params": {
    "n_gpu_layers": 0,
    "n_threads": 4,
    "n_batch": 64,
    "use_mmap": true
  }
}
```

---

## 🏢 Enterprise Configurations

### High Availability Setup

```json
{
  "provider": "openai",
  "model_name": "gpt-4-turbo",
  "api_base": "https://your-enterprise-endpoint.com/v1",
  "context_length": 32768,
  "temperature": 0.5,
  "max_tokens": 4096,
  "custom_params": {
    "timeout": 60,
    "max_retries": 3,
    "organization": "your-org-id",
    "headers": {
      "Authorization": "Bearer your-token"
    }
  }
}
```

### Load Balanced Local Deployment

```json
{
  "provider": "local_api",
  "model_name": "enterprise-security-model",
  "api_base": "http://load-balancer.internal:8080/v1",
  "context_length": 8192,
  "temperature": 0.4,
  "max_tokens": 2048,
  "custom_params": {
    "timeout": 120,
    "verify_ssl": true,
    "headers": {
      "X-API-Key": "your-internal-key"
    }
  }
}
```

---

## 🧪 Development & Testing

### Debug Configuration

```json
{
  "provider": "ollama",
  "model_name": "llama2:7b",
  "api_base": "http://localhost:11434",
  "context_length": 2048,
  "temperature": 0.1,
  "max_tokens": 1024,
  "custom_params": {
    "seed": 42,
    "top_p": 0.9,
    "repeat_penalty": 1.0,
    "debug": true,
    "verbose": true
  }
}
```

### A/B Testing Setup

```json
{
  "models": [
    {
      "name": "model_a",
      "provider": "openai",
      "model_name": "gpt-3.5-turbo",
      "weight": 0.5
    },
    {
      "name": "model_b",
      "provider": "anthropic",
      "model_name": "claude-3-haiku-20240307",
      "weight": 0.5
    }
  ],
  "selection_strategy": "random",
  "logging": true
}
```

---

## 🚀 Getting Started Checklist

### For Beginners
1. ✅ Start with OpenAI GPT-4 configuration
2. ✅ Get API key and test basic functionality
3. ✅ Try Frida script generation
4. ✅ Move to local models when comfortable

### For Advanced Users
1. ✅ Set up local GGUF or PyTorch backend
2. ✅ Experiment with quantization options
3. ✅ Fine-tune parameters for your use case
4. ✅ Set up monitoring and logging

### For Researchers
1. ✅ Use PyTorch backend for maximum flexibility
2. ✅ Enable custom model loading
3. ✅ Set up experimental configurations
4. ✅ Implement custom evaluation metrics

---

## 📊 Configuration Templates

Save these as `.json` files in your Intellicrack config directory:

### `fast-analysis.json`
```json
{
  "name": "Fast Analysis",
  "description": "Quick script generation and basic analysis",
  "provider": "openai",
  "model_name": "gpt-3.5-turbo",
  "context_length": 4096,
  "temperature": 0.3,
  "max_tokens": 1024
}
```

### `deep-research.json`
```json
{
  "name": "Deep Research",
  "description": "Comprehensive vulnerability analysis",
  "provider": "anthropic",
  "model_name": "claude-3-opus-20240229",
  "context_length": 200000,
  "temperature": 0.7,
  "max_tokens": 8192
}
```

### `local-privacy.json`
```json
{
  "name": "Local Privacy",
  "description": "Private local analysis",
  "provider": "local_gguf",
  "model_path": "/models/codellama-7b.gguf",
  "context_length": 8192,
  "temperature": 0.5,
  "max_tokens": 2048
}
```

---

*These configurations are starting points. Adjust parameters based on your specific hardware, use case, and performance requirements.*
