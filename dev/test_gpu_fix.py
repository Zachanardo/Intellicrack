#!/usr/bin/env python3
"""Test GPU detection fix"""

def test_gpu_classification():
    """Test the new GPU classification logic"""
    
    # Test cases based on your actual GPUs
    test_gpus = [
        ("Intel(R) Arc(TM) Graphics", "Intel"),  # Your integrated GPU (should be integrated)
        ("Intel(R) Arc(TM) B580 Graphics", "Intel"),  # Your discrete GPU (should be discrete)
        ("Intel(R) Arc(TM) A770 Graphics", "Intel"),  # Discrete
        ("Intel(R) UHD Graphics", "Intel"),  # Integrated
        ("NVIDIA GeForce RTX 4080", "NVIDIA"),  # Discrete
        ("AMD Radeon RX 7900 XT", "AMD"),  # Discrete
    ]
    
    print("Testing GPU classification logic:")
    print("=" * 60)
    
    for gpu_name, vendor in test_gpus:
        gpu_lower = gpu_name.lower()
        
        # Intel discrete GPUs - exclude generic "arc graphics" (integrated)
        intel_discrete = any(keyword in gpu_lower for keyword in [
            'a770', 'a750', 'a580', 'a380', 'b580', 'b770'
        ]) and 'arc' in gpu_lower
        
        # Additional check for Intel Arc B580 specifically
        if 'b580' in gpu_lower:
            intel_discrete = True
        elif gpu_lower == 'intel(r) arc(tm) graphics':
            intel_discrete = False
        
        # NVIDIA and AMD discrete detection
        nvidia_discrete = any(keyword in gpu_lower for keyword in [
            'rtx', 'gtx', 'titan', 'quadro'
        ])
        
        amd_discrete = any(keyword in gpu_lower for keyword in [
            'rx', 'radeon rx', 'vega', 'navi'
        ])
        
        is_discrete = intel_discrete or nvidia_discrete or amd_discrete
        gpu_type = "Discrete" if is_discrete else "Integrated"
        
        print(f"{gpu_name:<35} | {vendor:<7} | {gpu_type}")

if __name__ == "__main__":
    test_gpu_classification()