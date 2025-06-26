#!/usr/bin/env python3
"""
Train Advanced Licensing Detection Model

This script trains the new state-of-the-art licensing detection model
using streaming approach (no local binary storage required).
"""

import sys
import os
import time
import logging
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from intellicrack.models import get_ml_system, get_current_model_info

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_model():
    """Train the advanced licensing detection model"""
    print("=" * 80)
    print("INTELLICRACK ADVANCED ML MODEL TRAINING")
    print("=" * 80)
    print()
    
    # Get ML system
    ml_system = get_ml_system()
    
    # Check current status
    status = ml_system.get_training_status()
    print("Current Model Status:")
    print(f"  - Model Loaded: {status['model_loaded']}")
    print(f"  - Model Exists: {status['model_exists']}")
    print(f"  - Model Size: {status['model_size_mb']:.2f} MB")
    print()
    
    if status['model_loaded']:
        response = input("Model already exists. Retrain? (y/N): ")
        if response.lower() != 'y':
            print("Training cancelled.")
            return
    
    print("Training Configuration:")
    print("  - Method: Streaming (no local storage)")
    print("  - Sources: Trial software, GitHub releases, Gaming platforms")
    print("  - Target: 5,000+ binaries")
    print("  - Features: 200+ advanced features")
    print("  - Output: Multi-class protection classifier")
    print()
    
    print("Protection Types to Detect:")
    protection_types = [
        "1. Sentinel HASP (Hardware dongles)",
        "2. FlexLM/FlexNet (Network licensing)",
        "3. CodeMeter (Hardware/Software)",
        "4. WinLicense/Themida (Virtualization)",
        "5. VMProtect (Code virtualization)",
        "6. Steam CEG (Gaming DRM)",
        "7. Denuvo (Anti-tamper)",
        "8. Microsoft Activation",
        "9. Custom/Unknown schemes"
    ]
    for ptype in protection_types:
        print(f"  - {ptype}")
    print()
    
    response = input("Start training? This will take 3-5 hours. (y/N): ")
    if response.lower() != 'y':
        print("Training cancelled.")
        return
    
    print("\nStarting training process...")
    print("This will:")
    print("1. Collect URLs from legitimate sources")
    print("2. Stream binaries for feature extraction")
    print("3. Train ensemble model (LightGBM + XGBoost + RF)")
    print("4. Save optimized model (~500MB-1.5GB)")
    print()
    
    # Progress callback
    start_time = time.time()
    last_update = 0
    
    def progress_callback(current, total, result=None):
        nonlocal last_update
        
        if result:
            # Training complete
            elapsed = time.time() - start_time
            print(f"\n\nTraining Complete!")
            print(f"Time elapsed: {elapsed/3600:.2f} hours")
            print(f"Results:")
            print(f"  - Accuracy: {result.get('accuracy', 0):.2%}")
            print(f"  - Classes: {result.get('classes', 0)}")
            print(f"  - Samples: {result.get('samples', 0)}")
            print(f"  - Features: {result.get('features', 0)}")
            
            if 'report' in result:
                print("\nPer-class Performance:")
                report = result['report']
                for class_name in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']:
                    if class_name in report:
                        metrics = report[class_name]
                        print(f"  Class {class_name}: "
                              f"Precision={metrics['precision']:.2f}, "
                              f"Recall={metrics['recall']:.2f}, "
                              f"F1={metrics['f1-score']:.2f}")
        
        elif current == -1:
            # Error occurred
            print(f"\n\nTraining Error: {result.get('error', 'Unknown error')}")
        
        else:
            # Progress update
            now = time.time()
            if now - last_update > 1:  # Update every second
                last_update = now
                elapsed = now - start_time
                percent = (current / total * 100) if total > 0 else 0
                
                # Estimate time remaining
                if current > 0:
                    rate = current / elapsed
                    remaining = (total - current) / rate
                    eta = time.strftime('%H:%M:%S', time.gmtime(remaining))
                else:
                    eta = "calculating..."
                
                print(f"\rProgress: {current}/{total} ({percent:.1f}%) - "
                      f"Elapsed: {elapsed:.0f}s - ETA: {eta}    ", end='')
    
    # Start training
    result = ml_system.train_model(
        progress_callback=progress_callback,
        use_cached_urls=True  # Use cached URLs if available
    )
    
    if result['success']:
        print("\nTraining started successfully!")
        print("Training is running in the background...")
        
        # Wait for completion
        while ml_system.training_in_progress:
            time.sleep(1)
        
        # Verify model loaded
        if ml_system.model_loaded:
            print("\n\nModel successfully loaded and ready for use!")
            
            # Show model info
            model_info = get_current_model_info()
            print(f"\nModel Information:")
            print(f"  - Type: {model_info['type']}")
            print(f"  - Size: {model_info['size_mb']:.2f} MB")
            print(f"  - Capabilities:")
            for cap in model_info['capabilities']:
                print(f"    • {cap}")
            
            # Test prediction
            print("\n\nTesting model with sample prediction...")
            test_result = ml_system.predict("C:/Windows/System32/cmd.exe")
            print(f"Test Result:")
            print(f"  - Protection: {test_result.get('protection_type', 'Unknown')}")
            print(f"  - Confidence: {test_result.get('confidence', 0):.2%}")
            print(f"  - Difficulty: {test_result.get('bypass_difficulty', 'Unknown')}")
        else:
            print("\n\nWarning: Model training completed but failed to load.")
    else:
        print(f"\n\nFailed to start training: {result.get('error', 'Unknown error')}")


def main():
    """Main entry point"""
    try:
        train_model()
    except KeyboardInterrupt:
        print("\n\nTraining interrupted by user.")
    except Exception as e:
        logger.error(f"Training error: {e}", exc_info=True)
        print(f"\n\nError: {e}")


if __name__ == "__main__":
    main()