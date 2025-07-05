#!/usr/bin/env python3
"""
Intellicrack Launcher
Launch the Intellicrack application with proper environment setup.
"""

import os
import sys
from pathlib import Path


def detect_and_configure_gpu():
    """
    Auto-detect GPU and configure environment for optimal performance.
    
    This function performs comprehensive GPU detection across multiple backends
    (OpenCL, PyTorch, DirectML) and applies vendor-specific optimizations for
    Intel, NVIDIA, and AMD GPUs. It configures environment variables for optimal
    performance based on the detected hardware.
    
    Returns:
        tuple: A tuple containing:
            - gpu_detected (bool): Whether a GPU was successfully detected
            - gpu_type (str): Description of the detected GPU (e.g., "Intel Arc A770")
            - gpu_vendor (str): GPU vendor name ("Intel", "NVIDIA", "AMD", or "Unknown")
    
    Side Effects:
        Sets multiple environment variables for GPU optimization including:
        - MKL and OpenMP settings for CPU optimization
        - OpenCL context configuration
        - PyTorch backend settings
        - Qt rendering backend configuration
        - Vendor-specific GPU optimizations
    """
    print("=" * 60)
    print("INTELLICRACK GPU AUTO-DETECTION")
    print("=" * 60)
    print("Detecting GPU configuration...")

    # Set general optimization environment variables
    os.environ['MKL_SERVICE_FORCE_INTEL'] = '1'
    # Set OMP_NUM_THREADS based on CPU count
    try:
        import multiprocessing
        os.environ['OMP_NUM_THREADS'] = str(multiprocessing.cpu_count())
    except Exception:
        os.environ['OMP_NUM_THREADS'] = '4'

    # OpenCL optimizations (works for Intel, AMD, and NVIDIA)
    os.environ['PYOPENCL_COMPILER_OUTPUT'] = '1'
    os.environ['PYOPENCL_CTX'] = '0'  # Auto-select first GPU

    # PyTorch optimizations
    os.environ['PYTORCH_ENABLE_MPS_FALLBACK'] = '1'

    # Check for GPU availability
    gpu_detected = False
    gpu_type = "CPU"
    gpu_vendor = "Unknown"

    try:
        # First attempt: Use OpenCL to detect GPUs across all vendors
        import pyopencl as cl
        platforms = cl.get_platforms()
        for platform in platforms:
            devices = platform.get_devices(device_type=cl.device_type.GPU)
            if devices:
                gpu_detected = True
                device = devices[0]  # Use first available GPU
                gpu_type = device.name.strip()
                # Detect vendor from platform vendor string or device name
                vendor = platform.vendor.lower()
                if 'intel' in vendor or 'intel' in gpu_type.lower():
                    gpu_vendor = "Intel"
                elif 'nvidia' in vendor or 'nvidia' in gpu_type.lower():
                    gpu_vendor = "NVIDIA"
                elif 'amd' in vendor or 'amd' in gpu_type.lower():
                    gpu_vendor = "AMD"
                print(f"Detected GPU: {gpu_type} (Vendor: {gpu_vendor})")
                break
    except Exception as e:
        print(f"OpenCL GPU detection failed, trying PyTorch: {e}")

    if not gpu_detected:
        try:
            # Try unified GPU autoloader first
            from intellicrack.utils.gpu_autoloader import get_gpu_info, get_device
            gpu_info = get_gpu_info()
            if gpu_info['available']:
                gpu_detected = True
                gpu_type = gpu_info.get('device_name', 'Unknown GPU')
                device_str = get_device()
                
                # Determine vendor from GPU type
                gpu_type_lower = gpu_info.get('gpu_type', '').lower()
                if 'intel' in gpu_type_lower or 'xpu' in gpu_type_lower:
                    gpu_vendor = "Intel"
                    gpu_type = f"Intel {gpu_type} ({device_str})"
                elif 'nvidia' in gpu_type_lower or 'cuda' in gpu_type_lower:
                    gpu_vendor = "NVIDIA" 
                    gpu_type = f"NVIDIA {gpu_type} ({device_str})"
                elif 'amd' in gpu_type_lower or 'rocm' in gpu_type_lower:
                    gpu_vendor = "AMD"
                    gpu_type = f"AMD {gpu_type} ({device_str})"
                elif 'directml' in gpu_type_lower:
                    gpu_vendor = "DirectML"
                    gpu_type = f"DirectML {gpu_type}"
                else:
                    gpu_vendor = "Unknown"
                
                print(f"Detected GPU via unified loader: {gpu_type}")
                print(f"  Device count: {gpu_info.get('device_count', 1)}")
                print(f"  Memory: {gpu_info.get('memory_gb', 'Unknown')} GB")
                
        except ImportError:
            # Fall back to direct PyTorch detection
            try:
                import torch
                if hasattr(torch, 'xpu') and torch.xpu.is_available():
                    gpu_detected = True
                    gpu_vendor = "Intel"
                    gpu_type = f"Intel XPU ({torch.xpu.get_device_name(0)})"
                    print(f"Detected GPU: {gpu_type}")
                elif torch.cuda.is_available():
                    gpu_detected = True
                    gpu_vendor = "NVIDIA"
                    gpu_type = f"NVIDIA CUDA ({torch.cuda.get_device_name(0)})"
                    print(f"Detected GPU: {gpu_type}")
            except Exception as e:
                print(f"PyTorch GPU detection failed: {e}")

    # Apply vendor-specific optimizations
    if gpu_vendor == "Intel":
        print("Applying Intel GPU optimizations...")
        # Intel Arc/Iris/UHD specific settings
        os.environ['SYCL_DEVICE_FILTER'] = 'level_zero:gpu,opencl:gpu'
        os.environ['SYCL_PI_LEVEL_ZERO_USE_IMMEDIATE_COMMANDLISTS'] = '1'
        os.environ['INTEL_COMPUTE_BACKEND'] = 'level_zero,opencl'
        
        # Qt settings for Intel Arc Graphics - use ANGLE backend
        os.environ['QT_OPENGL'] = 'angle'  # Use ANGLE for Intel Arc compatibility
        os.environ['QT_ANGLE_PLATFORM'] = 'd3d11'
        os.environ['QSG_RENDER_LOOP'] = 'windows'  # Windows render loop for Intel
        os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '0'
        os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '0'
        os.environ['QT_SCALE_FACTOR'] = '1'
        os.environ['QT_D3D_ADAPTER_INDEX'] = '0'
        os.environ['QT_QUICK_BACKEND'] = 'software'  # Software backend for QtQuick
        
        # Force Qt to use DirectX instead of OpenGL
        os.environ['QT_QPA_PLATFORM'] = 'windows:darkmode=0'
        os.environ['QT_OPENGL_BUGLIST'] = '0'  # Disable OpenGL bug workarounds
        
        # Intel-specific workarounds
        os.environ['INTEL_DEBUG'] = 'nofc'  # Disable fast clear
        os.environ['QT_OPENGL_DLL'] = ''  # Don't force specific OpenGL DLL
        
    elif gpu_vendor == "NVIDIA":
        print("Applying NVIDIA GPU optimizations...")
        # NVIDIA specific settings
        os.environ['CUDA_CACHE_DISABLE'] = '0'  # Enable CUDA cache
        os.environ['CUDA_CACHE_MAXSIZE'] = '1073741824'  # 1GB cache
        os.environ['QT_OPENGL'] = 'desktop'  # Use hardware acceleration
        os.environ['QT_ANGLE_PLATFORM'] = 'd3d11'
        
    elif gpu_vendor == "AMD":
        print("Applying AMD GPU optimizations...")
        # AMD specific settings
        os.environ['HSA_ENABLE_SDMA'] = '0'  # Disable SDMA for stability
        os.environ['QT_OPENGL'] = 'desktop'  # Use hardware acceleration
        os.environ['QT_ANGLE_PLATFORM'] = 'd3d11'
        
    else:
        print("No GPU detected or unknown vendor. Using CPU mode...")
        # CPU fallback settings
        os.environ['QT_OPENGL'] = 'software'  # Software rendering for CPU
        os.environ['QT_QUICK_BACKEND'] = 'software'

    if not gpu_detected:
        print("Running in CPU mode with software rendering.")
    else:
        print(f"GPU acceleration configured for: {gpu_vendor} - {gpu_type}")

    return gpu_detected, gpu_type, gpu_vendor


def main():
    """
    Main entry point for the Intellicrack launcher.
    
    This function sets up the Python path, detects and configures GPU settings,
    and launches the main Intellicrack application. It includes special handling
    for Intel Arc Graphics crashes and can automatically restart in software
    rendering mode if needed.
    
    The function performs the following steps:
    1. Adds the project root to Python path for module imports
    2. Detects and configures GPU settings via detect_and_configure_gpu()
    3. Stores GPU information in environment variables for the app
    4. Checks for forced software rendering mode
    5. Imports and runs the main Intellicrack application
    6. Handles Intel Arc Graphics crash recovery with user prompt
    
    Returns:
        int: Exit code from the main application or recursive call result
    
    Environment Variables Set:
        - INTELLICRACK_GPU_DETECTED: "True" or "False" string
        - INTELLICRACK_GPU_TYPE: GPU description string
        - INTELLICRACK_GPU_VENDOR: Vendor name string
        - INTELLICRACK_FORCE_SOFTWARE: "1" to force software rendering
    
    Raises:
        ImportError: If Intellicrack modules cannot be imported
        Exception: For any other startup errors
    """
    # Add the intellicrack package to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))

    # Auto-detect and configure GPU
    gpu_detected, gpu_type, gpu_vendor = detect_and_configure_gpu()

    # Store GPU info in environment for the app to use
    os.environ['INTELLICRACK_GPU_DETECTED'] = str(gpu_detected)
    os.environ['INTELLICRACK_GPU_TYPE'] = gpu_type
    os.environ['INTELLICRACK_GPU_VENDOR'] = gpu_vendor

    # Check if we should force software rendering (fallback mode)
    if os.environ.get('INTELLICRACK_FORCE_SOFTWARE', '0') == '1':
        print("\n" + "=" * 60)
        print("RUNNING IN SOFTWARE RENDERING MODE (FALLBACK)")
        print("=" * 60)
        os.environ['QT_OPENGL'] = 'software'
        os.environ['QT_QUICK_BACKEND'] = 'software'
        os.environ.pop('QT_ANGLE_PLATFORM', None)
        os.environ.pop('QSG_RENDER_LOOP', None)

    try:
        # Import and run the main application
        print("Importing intellicrack.main...")
        from intellicrack.main import main as intellicrack_main
        print("Successfully imported intellicrack.main")
        
        print("Calling intellicrack_main()...")
        exit_code = intellicrack_main()
        print(f"intellicrack_main() returned: {exit_code}")
        
        # Check for Intel Arc crash (specific exit code -805306369 indicates Qt/OpenGL crash)
        if exit_code == -805306369 and gpu_vendor == "Intel":
            print("\n" + "=" * 60)
            print("INTEL ARC GRAPHICS CRASH DETECTED")
            print("=" * 60)
            print("The application crashed due to Intel Arc Graphics compatibility issues.")
            print("Would you like to restart in software rendering mode? (Y/N)")
            response = input("> ").strip().upper()
            if response == 'Y':
                os.environ['INTELLICRACK_FORCE_SOFTWARE'] = '1'
                print("Restarting in software rendering mode...")
                return main()  # Recursive call with software mode enabled
        
        sys.exit(exit_code)
    except ImportError as e:
        print(f"ERROR: Failed to import Intellicrack: {e}")
        print("Make sure all dependencies are installed.")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start Intellicrack: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
