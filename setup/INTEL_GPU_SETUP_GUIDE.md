# Intel GPU Setup Guide for Intel Extension for PyTorch (IPEX)

This guide covers the complete setup process for Intel Arc/Iris GPUs with PyTorch and IPEX on Windows.

## Prerequisites

### 1. Intel GPU Drivers
- **Intel Arc/Iris Xe GPU** with latest DCH drivers
- Download from: [Intel Driver & Support Assistant](https://www.intel.com/content/www/us/en/support/detect.html)
- Or direct: [Intel Graphics Drivers](https://www.intel.com/content/www/us/en/download/726609/intel-arc-iris-xe-graphics-windows.html)

### 2. Intel GPU Compute Runtime
Required for GPU compute capabilities:
- [Intel Compute Runtime](https://github.com/intel/compute-runtime/releases)
- Download the latest `.exe` installer for Windows

### 3. Intel oneAPI Base Toolkit
Provides essential runtime libraries:
- [Intel oneAPI Base Toolkit](https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit-download.html)
- Choose "Windows" and "Offline Installer" or "Online Installer"
- **Minimum components needed:**
  - Intel oneAPI DPC++/C++ Compiler
  - Intel oneAPI Math Kernel Library (oneMKL)
  - Intel oneAPI Threading Building Blocks (oneTBB)

### 4. Visual C++ Redistributables
- [Microsoft Visual C++ Redistributable](https://aka.ms/vs/16/release/vc_redist.x64.exe)
- Required for DLL dependencies

## Installation Steps

### Step 1: Install Intel GPU Drivers
1. Download and run Intel Driver installer
2. Restart your computer after installation
3. Verify installation: Open Device Manager → Display adapters → Should show "Intel(R) Arc(TM)" or "Intel(R) Iris(R) Xe"

### Step 2: Install Intel GPU Compute Runtime
1. Download the latest `intel-opencl-icd-*.exe`
2. Run as Administrator
3. Follow installation wizard

### Step 3: Install Intel oneAPI Base Toolkit
1. Download and run the installer
2. Select "Custom Installation"
3. Choose at minimum:
   - DPC++/C++ Compiler
   - Math Kernel Library
   - Threading Building Blocks
4. Install to default location: `C:\Program Files (x86)\Intel\oneAPI`

### Step 4: Fix Missing DLLs (if needed)
Intel DCH drivers may install DLLs to DriverStore instead of System32. Run this batch script as Administrator:

```batch
@echo off
echo Copying Intel GPU DLLs from DriverStore to System32...

REM Find the Intel driver directory
for /d %%i in (C:\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*) do set DRIVER_DIR=%%i

REM Copy essential DLLs
copy /Y "%DRIVER_DIR%\ze_intel_gpu64.dll" "C:\Windows\System32\"
copy /Y "%DRIVER_DIR%\ze_loader.dll" "C:\Windows\System32\"
copy /Y "%DRIVER_DIR%\igdrcl64.dll" "C:\Windows\System32\"
copy /Y "%DRIVER_DIR%\igdfcl64.dll" "C:\Windows\System32\"

echo Done!
pause
```

### Step 5: Install PyTorch with XPU Support

**CRITICAL**: You must install the XPU version of PyTorch, NOT the regular CPU or CUDA versions.

```bash
# Uninstall existing PyTorch (if any)
pip uninstall -y torch torchvision torchaudio

# Install PyTorch XPU version
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/xpu
```

### Step 6: Install Intel Extension for PyTorch

```bash
# Install IPEX with XPU support
pip install intel-extension-for-pytorch --extra-index-url https://pytorch-extension.intel.com/release-whl/stable/xpu/us/
```

## Verification

### Test Installation
Create a test script `test_intel_gpu.py`:

```python
import torch
import intel_extension_for_pytorch as ipex

print(f"PyTorch version: {torch.__version__}")
print(f"IPEX version: {ipex.__version__}")
print(f"XPU available: {torch.xpu.is_available()}")

if torch.xpu.is_available():
    device_count = torch.xpu.device_count()
    print(f"Number of XPU devices: {device_count}")

    for i in range(device_count):
        props = torch.xpu.get_device_properties(i)
        print(f"\nDevice {i}: {props.name}")
        print(f"  Total Memory: {props.total_memory / 1024**3:.2f} GB")
        print(f"  Driver Version: {props.driver_version}")

    # Test computation
    device = "xpu:0"
    x = torch.randn(1000, 1000).to(device)
    y = torch.randn(1000, 1000).to(device)
    z = torch.matmul(x, y)
    print(f"\nMatrix multiplication successful on {z.device}")
```

Run: `python test_intel_gpu.py`

Expected output:
```
PyTorch version: 2.7.1+xpu
IPEX version: 2.7.10+xpu
XPU available: True
Number of XPU devices: 1

Device 0: Intel(R) Arc(TM) B580 Graphics
  Total Memory: 11.60 GB
  Driver Version: 1.6.33890

Matrix multiplication successful on xpu:0
```

## Troubleshooting

### Common Issues

#### 1. "WinError 126: The specified module could not be found"
- **Cause**: Missing Intel GPU runtime DLLs
- **Solution**: Run the DLL copy script in Step 4 as Administrator

#### 2. "intel-ext-pt-gpu-bitsandbytes.dll" error
- **Cause**: Version mismatch between PyTorch and IPEX
- **Solution**: Ensure you're using PyTorch XPU version from the correct index URL

#### 3. "XPU not available" despite having Intel GPU
- **Cause**: Missing or outdated drivers/runtime
- **Solution**:
  1. Update Intel GPU drivers
  2. Install Intel Compute Runtime
  3. Reinstall PyTorch XPU version

#### 4. Environment Variables
Add to system PATH if not automatically added:
```
C:\Program Files (x86)\Intel\oneAPI\compiler\latest\bin
C:\Program Files (x86)\Intel\oneAPI\mkl\latest\bin
```

### Version Compatibility

| PyTorch Version | IPEX Version | Index URL |
|----------------|--------------|-----------|
| 2.7.1+xpu | 2.7.10+xpu | https://download.pytorch.org/whl/xpu |
| 2.5.1+cxx11.abi | 2.5.10+xpu | https://pytorch-extension.intel.com/release-whl/stable/xpu/us/ |

**Important**: Always match PyTorch and IPEX major.minor versions (e.g., 2.7.x with 2.7.x)

## Performance Tips

1. **Memory Management**: Set environment variable for large allocations:
   ```python
   import os
   os.environ["UR_L0_ENABLE_RELAXED_ALLOCATION_LIMITS"] = "1"
   ```

2. **Optimization**: Use IPEX optimize for inference:
   ```python
   model.eval()
   optimized_model = ipex.optimize(model)
   ```

3. **Mixed Precision**: Use bfloat16 for better performance:
   ```python
   with torch.xpu.amp.autocast(dtype=torch.bfloat16):
       output = model(input)
   ```

## Additional Resources

- [Intel Extension for PyTorch Documentation](https://intel.github.io/intel-extension-for-pytorch/)
- [PyTorch XPU Documentation](https://pytorch.org/docs/stable/xpu.html)
- [Intel GPU Troubleshooting](https://www.intel.com/content/www/us/en/support/articles/000058314/graphics.html)
- [IPEX GitHub Issues](https://github.com/intel/intel-extension-for-pytorch/issues)

## Notes

- The warnings about operator overriding and pkg_resources deprecation are normal and don't affect functionality
- Intel Arc GPUs require Windows 10 20H2 or later, Windows 11 recommended
- WSL2 is not recommended for Intel GPU compute; use native Windows instead
