#!/usr/bin/env python3
"""Test script to verify Rust launcher environment configuration."""

import os
import sys
import json

def test_environment():
    """Check all environment variables that should be set by the Rust launcher."""
    
    results = {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "python_executable": sys.executable,
        "working_dir": os.getcwd(),
        "environment_variables": {}
    }
    
    # Critical environment variables from the Rust launcher
    critical_vars = [
        # PyBind11 GIL Safety
        "PYBIND11_NO_ASSERT_GIL_HELD_INCREF_DECREF",
        
        # Threading configuration
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS", 
        "NUMEXPR_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "BLIS_NUM_THREADS",
        
        # PyTorch configuration  
        "PYTORCH_DISABLE_CUDNN_BATCH_NORM",
        "CUDA_LAUNCH_BLOCKING",
        
        # Intel GPU settings
        "CUDA_VISIBLE_DEVICES",
        "INTELLICRACK_GPU_TYPE",
        "QT_OPENGL",
        "QT_ANGLE_PLATFORM",
        "QT_D3D_ADAPTER_INDEX",
        "QT_QUICK_BACKEND",
        "QT_QPA_PLATFORM",
        
        # TensorFlow
        "TF_CPP_MIN_LOG_LEVEL",
        "MKL_THREADING_LAYER",
        
        # Windows-specific
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        
        # Qt logging
        "QT_LOGGING_RULES"
    ]
    
    for var in critical_vars:
        value = os.environ.get(var)
        results["environment_variables"][var] = {
            "set": value is not None,
            "value": value
        }
    
    # Check if sys.setcheckinterval is available
    results["setcheckinterval_available"] = hasattr(sys, "setcheckinterval")
    
    # Test if we can import intellicrack (expected to fail in test)
    try:
        import intellicrack.main
        results["intellicrack_available"] = True
        results["intellicrack_path"] = intellicrack.__file__
    except ImportError as e:
        results["intellicrack_available"] = False
        results["intellicrack_error"] = str(e)
    
    return results

if __name__ == "__main__":
    print("=== Rust Launcher Environment Test ===\n")
    
    results = test_environment()
    
    # Check critical variables
    all_set = True
    missing_vars = []
    
    for var, info in results["environment_variables"].items():
        if not info["set"]:
            all_set = False
            missing_vars.append(var)
            print(f"❌ {var}: NOT SET")
        else:
            print(f"✅ {var}: {info['value']}")
    
    print(f"\nPython Version: {results['python_version']}")
    print(f"Python Executable: {results['python_executable']}")
    print(f"Working Directory: {results['working_dir']}")
    print(f"setcheckinterval available: {results['setcheckinterval_available']}")
    print(f"Intellicrack module available: {results['intellicrack_available']}")
    
    if missing_vars:
        print(f"\n⚠️  Missing environment variables: {', '.join(missing_vars)}")
        sys.exit(1)
    else:
        print("\n✅ All critical environment variables are set!")
        
    # Save detailed results
    with open("rust_launcher_env_test_results.json", "w") as f:
        json.dump(results, f, indent=2)
        print(f"\nDetailed results saved to: rust_launcher_env_test_results.json")
        
    sys.exit(0)