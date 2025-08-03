#!/usr/bin/env python3
"""Direct test of entropy module without full Intellicrack initialization."""

import sys
import os
import numpy as np
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

try:
    # Direct import without going through main intellicrack init
    from intellicrack.protection.entropy_packer_detector import (
        AdvancedEntropyCalculator, 
        PackerSignatureDatabase,
        SophisticatedEntropyPackerDetector
    )
    
    # Test entropy calculation
    calc = AdvancedEntropyCalculator()
    test_data = b"Hello World! This is test data for entropy calculation." * 100
    
    shannon = calc.calculate_shannon_entropy(test_data)
    renyi = calc.calculate_renyi_entropy(test_data, alpha=2.0)
    
    print(f"Shannon entropy: {shannon:.4f}")
    print(f"Renyi entropy: {renyi:.4f}")
    
    # Test packer signature database
    db = PackerSignatureDatabase()
    print(f"Loaded {len(db.signatures)} packer signatures")
    
    # Test detector creation
    detector = SophisticatedEntropyPackerDetector()
    print("Detector created successfully")
    
    print("✓ All entropy detection components working correctly!")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()