# Mamba + UV + Intel GPU Setup Guide

This guide documents the exact process for setting up a mamba environment with UV for Python package management and Intel GPU support for PyTorch/IPEX.

## Prerequisites

1. **Miniforge/Mambaforge** installed
2. **UV** package manager
3. **Intel Arc/Iris GPU** with latest drivers
4. **Windows 10 20H2+** or Windows 11

## Step 1: Create Mamba Environment

```bash
# Create a new mamba environment with Python 3.12
mamba create -n intellicrack python=3.12 -y

# Activate the environment
mamba activate intellicrack
```

## Step 2: Install UV in Mamba Environment

```bash
# Install UV using pip within the mamba environment
pip install uv
```

## Step 3: Install Base Dependencies with UV

```bash
# Install core dependencies using UV
uv pip install numpy scipy matplotlib pandas
uv pip install psutil packaging ruamel.yaml
```

## Step 4: Install Intel GPU Prerequisites

### 4.1 Intel oneAPI Runtime Components
These are typically installed via mamba or system-wide:

```bash
# Install Intel runtime libraries
mamba install -c intel dpcpp-cpp-rt mkl-dpcpp intel-openmp -y
```

### 4.2 Fix Missing Intel GPU DLLs
Intel DCH drivers often install DLLs to DriverStore instead of System32. As Administrator, run:

```batch
# Copy Intel GPU runtime DLLs to System32
copy "C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\ze_intel_gpu64.dll" "C:\Windows\System32\"
copy "C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\ze_loader.dll" "C:\Windows\System32\"
copy "C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\igdrcl64.dll" "C:\Windows\System32\"
copy "C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\igdfcl64.dll" "C:\Windows\System32\"
```

## Step 5: Install PyTorch XPU Version

**CRITICAL**: You must install the XPU version, not CPU or CUDA versions.

```bash
# Remove any existing PyTorch installation
uv pip uninstall torch torchvision torchaudio

# Install PyTorch XPU version
uv pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/xpu
```

Expected versions:
- torch==2.7.1+xpu
- torchvision==0.22.1+xpu
- torchaudio==2.7.1+xpu

## Step 6: Install Intel Extension for PyTorch (IPEX)

```bash
# Install IPEX with the correct index URL
uv pip install intel-extension-for-pytorch==2.7.10+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
```

## Step 7: Environment Variables

Add Intel oneAPI to your PATH (if not already done):

```batch
# Add to system environment variables
C:\Program Files (x86)\Intel\oneAPI\compiler\latest\bin
C:\Program Files (x86)\Intel\oneAPI\mkl\latest\bin
```

Or create a `.pth` file in your mamba environment:
```python
# Create file: mamba_env\Lib\site-packages\intel_paths.pth
import os; os.environ['PATH'] = r'C:\Program Files (x86)\Intel\oneAPI\compiler\latest\bin;' + os.environ.get('PATH', '')
```

## Step 8: Verify Installation

Create and run this verification script:

```python
# verify_intel_gpu.py
import torch
import intel_extension_for_pytorch as ipex

print("=== Intel GPU Setup Verification ===")
print(f"PyTorch version: {torch.__version__}")
print(f"IPEX version: {ipex.__version__}")
print(f"Python: {sys.version}")

# Check XPU availability
if torch.xpu.is_available():
    print(f"\n✓ XPU is available!")
    print(f"Device count: {torch.xpu.device_count()}")

    for i in range(torch.xpu.device_count()):
        props = torch.xpu.get_device_properties(i)
        print(f"\nDevice {i}: {props.name}")
        print(f"  Memory: {props.total_memory / 1024**3:.2f} GB")
        print(f"  Compute Units: {props.max_compute_units}")
        print(f"  Driver: {props.driver_version}")
else:
    print("\n✗ XPU not available - check troubleshooting section")
```

## Troubleshooting

### Issue 1: "WinError 126: The specified module could not be found"

**Symptom**: Error loading intel-ext-pt-gpu-bitsandbytes.dll

**Cause**: Either missing Intel runtime DLLs or wrong PyTorch version

**Solution**:
1. Verify you have PyTorch XPU version: `torch.__version__` should show `+xpu`
2. Check Intel DLLs are in System32 (see Step 4.2)
3. If you have bitsandbytes installed, uninstall it: `uv pip uninstall bitsandbytes`

### Issue 2: Version Mismatch Errors

**Symptom**: "Intel Extension for PyTorch needs to work with PyTorch X.X"

**Solution**: Ensure version compatibility:
- PyTorch 2.7.1+xpu ↔ IPEX 2.7.10+xpu
- PyTorch 2.5.1+cxx11.abi ↔ IPEX 2.5.10+xpu

### Issue 3: XPU Not Detected

**Symptom**: `torch.xpu.is_available()` returns False

**Solution**:
1. Update Intel GPU drivers from [Intel's website](https://www.intel.com/content/www/us/en/support/detect.html)
2. Install [Intel Compute Runtime](https://github.com/intel/compute-runtime/releases)
3. Ensure you're NOT in WSL - use native Windows
4. Check Device Manager shows Intel Arc/Iris GPU

### Issue 4: Missing Dependencies

**Symptom**: ImportError for various Intel libraries

**Solution**: Install missing components via mamba:
```bash
mamba install -c intel intel-opencl-rt intel-sycl-rt tbb umf tcmlib
```

## Important Notes

1. **Package Manager Priority**:
   - Use `uv pip` for Python packages
   - Use `mamba` for system libraries and Intel runtime components

2. **Index URLs**:
   - PyTorch XPU: `https://download.pytorch.org/whl/xpu`
   - IPEX: `https://pytorch-extension.intel.com/release-whl/stable/xpu/us/`

3. **Common Warnings** (safe to ignore):
   - "Overriding a previously registered kernel" - Normal IPEX behavior
   - "pkg_resources is deprecated" - Known issue, doesn't affect functionality

4. **Performance Tips**:
   ```python
   # Enable large memory allocations
   os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = "1"

   # Use IPEX optimization for inference
   model.eval()
   model = ipex.optimize(model)
   ```

## Complete Installation Commands Summary

```bash
# 1. Create and activate mamba environment
mamba create -n intellicrack python=3.12 -y
mamba activate intellicrack

# 2. Install UV
pip install uv

# 3. Install Intel runtime via mamba
mamba install -c intel dpcpp-cpp-rt mkl-dpcpp intel-openmp -y

# 4. Install PyTorch XPU
uv pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/xpu

# 5. Install IPEX
uv pip install intel-extension-for-pytorch==2.7.10+xpu --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/

# 6. Verify
python -c "import torch; import intel_extension_for_pytorch as ipex; print(f'XPU: {torch.xpu.is_available()}')"
```

## References

- [IPEX XPU Installation](https://intel.github.io/intel-extension-for-pytorch/xpu/latest/tutorials/installation.html)
- [PyTorch XPU Support](https://pytorch.org/docs/stable/xpu.html)
- [Intel GPU Compute Runtime](https://github.com/intel/compute-runtime)
- [Known Issues](https://github.com/intel/intel-extension-for-pytorch/issues)
