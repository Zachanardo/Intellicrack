# GPU Acceleration Guide

## Overview

Intellicrack supports GPU acceleration for computationally intensive operations including pattern matching, hash calculation, and AI model inference. This guide covers setup and optimization for NVIDIA, AMD, and Intel GPUs.

## Supported GPUs

### NVIDIA GPUs
- **Requirements**: CUDA 11.8+ or 12.1+
- **Recommended**: RTX 3060 or newer
- **Driver**: 525.60.13 or newer

### AMD GPUs
- **Requirements**: ROCm 5.4.2+ (Linux only)
- **Recommended**: RX 6600 or newer
- **Note**: Windows support via DirectML

### Intel GPUs
- **Requirements**: Intel Arc A-series or newer
- **Supported**: Arc A380, A750, A770, B580
- **Driver**: Latest Intel Graphics Driver

## GPU Detection

Intellicrack automatically detects available GPUs on startup. Check the logs for:

```
GPU Status: Intel Arc B580 detected
GPU Memory: 12GB available
Acceleration: Enabled
```

## Configuration

### Automatic Configuration
The `RUN_INTELLICRACK.bat` script automatically configures GPU settings:

```batch
set CUDA_VISIBLE_DEVICES=-1        # Disable CUDA for Intel/AMD
set INTELLICRACK_GPU_TYPE=intel    # Set GPU type
```

### Manual Configuration

#### Environment Variables
```bash
# NVIDIA GPU
export INTELLICRACK_GPU_TYPE=nvidia
export CUDA_VISIBLE_DEVICES=0

# AMD GPU
export INTELLICRACK_GPU_TYPE=amd
export HSA_OVERRIDE_GFX_VERSION=10.3.0

# Intel GPU
export INTELLICRACK_GPU_TYPE=intel
export CUDA_VISIBLE_DEVICES=-1
```

#### Configuration File
Edit `config/intellicrack_config.json`:

```json
{
  "gpu": {
    "enabled": true,
    "type": "auto",
    "device_id": 0,
    "memory_fraction": 0.8,
    "fallback_to_cpu": true
  }
}
```

## GPU-Accelerated Features

### 1. Pattern Matching
- **Speed**: Up to 50x faster than CPU
- **Operations**: Binary pattern search, signature scanning
- **Memory**: Requires pattern size + 2GB overhead

### 2. Hash Calculation
- **Algorithms**: MD5, SHA1, SHA256, SHA512
- **Throughput**: 10GB/s+ on modern GPUs
- **Batch Processing**: Automatic for files > 100MB

### 3. AI Model Inference
- **Frameworks**: PyTorch, TensorFlow, ONNX
- **Quantization**: INT8/FP16 for better performance
- **Multi-GPU**: Supported for large models

### 4. Entropy Analysis
- **Block Size**: Configurable (default 4KB)
- **Visualization**: Real-time entropy graphs
- **Speed**: 100x faster than CPU

## Performance Optimization

### Memory Management
```python
# In Settings → Performance
gpu_config = {
    "max_memory_mb": 8192,        # Limit GPU memory usage
    "batch_size": 1024,           # Adjust for your GPU
    "pin_memory": True,           # Faster CPU-GPU transfer
    "async_transfer": True        # Non-blocking operations
}
```

### Batch Processing
For large file analysis:
1. Enable "GPU Batch Mode" in Settings
2. Set appropriate batch size (start with 256)
3. Monitor GPU memory usage

### Multi-GPU Setup
```python
# For systems with multiple GPUs
gpu_config = {
    "multi_gpu": True,
    "gpu_ids": [0, 1],           # Use GPUs 0 and 1
    "strategy": "split"          # or "duplicate"
}
```

## Troubleshooting

### GPU Not Detected
1. Check driver installation:
   ```bash
   # NVIDIA
   nvidia-smi

   # Intel
   xpu-smi discovery
   ```

2. Verify environment variables are set correctly

3. Check Settings → System Info for GPU status

### Out of Memory Errors
1. Reduce batch size in Settings
2. Lower memory fraction (default 0.8 → 0.6)
3. Enable CPU fallback for large operations

### Performance Issues
1. Ensure GPU is not thermal throttling
2. Close other GPU-intensive applications
3. Update to latest drivers
4. Disable Windows GPU scheduling

### Intel Arc Specific
If you see "GPU not available" with Intel Arc:
1. Set `QT_OPENGL=software` in environment
2. Use DirectML backend: `set INTELLICRACK_BACKEND=directml`
3. Update Intel Graphics Driver

## Benchmarking

Run GPU benchmark from Tools → GPU Benchmark:

```
Pattern Matching: 2.5 GB/s
Hash Calculation: 12.3 GB/s
Entropy Analysis: 8.7 GB/s
AI Inference: 145 tokens/s
```

Compare with CPU baseline to verify acceleration.

## Advanced Configuration

### Custom CUDA Kernels
Place custom CUDA kernels in `intellicrack/core/cuda/`:
```python
from intellicrack.core.gpu_acceleration import load_custom_kernel
kernel = load_custom_kernel("my_pattern_matcher.cu")
```

### DirectML Backend (Windows)
For AMD/Intel GPUs on Windows:
```python
config["gpu"]["backend"] = "directml"
config["gpu"]["directml_device"] = 0
```

### ROCm Configuration (Linux)
```bash
# For AMD GPUs
export ROCM_PATH=/opt/rocm
export HIP_VISIBLE_DEVICES=0
```

## Best Practices

1. **Start Small**: Test with small files before large-scale analysis
2. **Monitor Temperature**: GPU temps should stay below 80°C
3. **Profile First**: Use benchmark tool to find optimal settings
4. **Fallback Ready**: Always enable CPU fallback
5. **Update Drivers**: Keep GPU drivers current

## Supported Operations

| Operation | NVIDIA | AMD | Intel | Speedup |
|-----------|--------|-----|-------|---------|
| Pattern Search | ✅ | ✅ | ✅ | 10-50x |
| Hash Calculation | ✅ | ✅ | ✅ | 20-100x |
| Entropy Analysis | ✅ | ✅ | ✅ | 50-100x |
| AI Inference | ✅ | ⚠️ | ✅ | 5-20x |
| Symbolic Execution | ✅ | ❌ | ❌ | 2-5x |
| Binary Diffing | ✅ | ✅ | ✅ | 10-30x |

⚠️ = Limited support
❌ = Not supported

## Limitations

- GPU memory limits batch sizes
- Some operations require specific GPU capabilities
- DirectML backend has fewer features than CUDA
- Multi-GPU requires identical GPU models for best results
