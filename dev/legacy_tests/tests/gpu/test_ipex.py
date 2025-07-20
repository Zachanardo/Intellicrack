import sys
print(f"Python: {sys.version}")
print(f"Python executable: {sys.executable}")

try:
    import torch
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    
    import intel_extension_for_pytorch as ipex
    print(f"Intel Extension for PyTorch version: {ipex.__version__}")
    print("IPEX imported successfully!")
    
    # Check XPU availability
    print(f"XPU available: {torch.xpu.is_available()}")
    if torch.xpu.is_available():
        print(f"XPU device count: {torch.xpu.device_count()}")
        print(f"XPU device name: {torch.xpu.get_device_name(0)}")
        
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()