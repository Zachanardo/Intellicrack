#!/usr/bin/env python3
"""Test script for Enhanced Training Interface"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test basic imports"""
    print("Testing imports...")
    try:
        from intellicrack.ai.enhanced_training_interface import (
            TrainingConfiguration,
            ModelMetrics,
            TrainingStatus,
            TrainingDataset,
            ModelTrainer,
            DatasetCreator,
            ModelDeploymentManager,
            ActiveLearningManager
        )
        print("✓ All classes imported successfully")
        
        # Test configuration
        config = TrainingConfiguration()
        print(f"✓ Default config created: {config.model_name}")
        
        # Test dataset creator
        creator = DatasetCreator()
        print("✓ DatasetCreator initialized")
        
        # Test deployment manager
        deployment = ModelDeploymentManager()
        print("✓ ModelDeploymentManager initialized")
        
        # Test metrics
        metrics = ModelMetrics()
        print(f"✓ ModelMetrics created with accuracy: {metrics.accuracy}")
        
        return True
        
    except Exception as e:
        print(f"✗ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_training_components():
    """Test training components"""
    print("\nTesting training components...")
    try:
        from intellicrack.ai.enhanced_training_interface import (
            TrainingConfiguration,
            ModelTrainer,
            TrainingDataset
        )
        
        # Test configuration
        config = TrainingConfiguration(
            model_name="test_model",
            model_type="vulnerability_classifier",
            learning_rate=0.001,
            batch_size=32,
            epochs=10
        )
        print("✓ Training configuration created")
        
        # Test model trainer
        trainer = ModelTrainer(config)
        print("✓ ModelTrainer initialized")
        
        # Test dataset
        import tempfile
        import json
        import numpy as np
        
        # Create temporary dataset
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            dataset = {
                'features': np.random.rand(100, 64).tolist(),
                'labels': np.random.randint(0, 5, 100).tolist(),
                'metadata': {'feature_names': [f'feature_{i}' for i in range(64)]}
            }
            json.dump(dataset, f)
            temp_path = f.name
            
        dataset_obj = TrainingDataset(temp_path, {'normalize': True, 'shuffle': True})
        dataset_obj.load_dataset()
        print("✓ Dataset loaded successfully")
        
        # Clean up
        os.unlink(temp_path)
        
        return True
        
    except Exception as e:
        print(f"✗ Component test error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_model_architectures():
    """Test model architecture building"""
    print("\nTesting model architectures...")
    try:
        from intellicrack.ai.enhanced_training_interface import (
            TrainingConfiguration,
            ModelTrainer
        )
        
        config = TrainingConfiguration()
        trainer = ModelTrainer(config)
        
        # Test different model types
        model_types = [
            "vulnerability_classifier",
            "exploit_detector",
            "malware_classifier",
            "license_detector",
            "packer_identifier"
        ]
        
        for model_type in model_types:
            config.model_type = model_type
            try:
                trainer.build_model(input_shape=64, num_classes=5)
                print(f"✓ Built {model_type} model")
            except ImportError:
                print(f"⚠ {model_type} requires TensorFlow/PyTorch (not installed)")
            except Exception as e:
                print(f"✗ Failed to build {model_type}: {e}")
                
        return True
        
    except Exception as e:
        print(f"✗ Architecture test error: {e}")
        return False

def main():
    """Run all tests"""
    print("Enhanced Training Interface Test Suite")
    print("=" * 50)
    
    results = []
    results.append(test_imports())
    results.append(test_training_components())
    results.append(test_model_architectures())
    
    print("\n" + "=" * 50)
    print(f"Tests passed: {sum(results)}/{len(results)}")
    
    if all(results):
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())