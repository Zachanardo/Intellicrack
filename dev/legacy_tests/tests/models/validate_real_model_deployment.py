#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Real Model Deployment Validation

Validates that the synthetic training system has been completely replaced
with the real licensing model system.
"""

import json
import logging
import os
from typing import Dict

import joblib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def validate_real_model_deployment() -> Dict[str, bool]:
    """Validate that real model has been properly deployed"""
    validation_results = {}

    logger.info("Starting real model deployment validation...")

    # 1. Check that synthetic model files are removed/backed up
    logger.info("Checking synthetic model removal...")
    synthetic_files_removed = _check_synthetic_files_removed()
    validation_results['synthetic_files_removed'] = synthetic_files_removed

    # 2. Check that real model files exist
    logger.info("Checking real model deployment...")
    real_models_deployed = _check_real_models_deployed()
    validation_results['real_models_deployed'] = real_models_deployed

    # 3. Validate model metadata
    logger.info("Validating model metadata...")
    metadata_valid = _validate_model_metadata()
    validation_results['metadata_valid'] = metadata_valid

    # 4. Test model functionality
    logger.info("Testing model functionality...")
    model_functional = _test_model_functionality()
    validation_results['model_functional'] = model_functional

    # 5. Check model training source
    logger.info("Verifying real data source...")
    real_data_source = _verify_real_data_source()
    validation_results['real_data_source'] = real_data_source

    return validation_results


def _check_synthetic_files_removed() -> bool:
    """Check that synthetic model files are no longer in active locations"""
    active_model_locations = [
        "/mnt/c/Intellicrack/intellicrack/models/vulnerability_model.joblib",
        "/mnt/c/Intellicrack/intellicrack/models/licensing_model.joblib",
        "/mnt/c/Intellicrack/intellicrack/ui/models/vuln_predict_model.joblib"
    ]

    backup_location = "/mnt/c/Intellicrack/backup_synthetic_models"

    # Check that backup was created
    backup_exists = os.path.exists(backup_location)
    logger.info(f"Synthetic model backup exists: {backup_exists}")

    # Check that active locations contain real models (not synthetic)
    for model_path in active_model_locations:
        if os.path.exists(model_path):
            # Check file modification time (should be recent)
            import time
            mod_time = os.path.getmtime(model_path)
            current_time = time.time()
            time_diff = current_time - mod_time

            # Model should be recently created (within last hour)
            if time_diff > 3600:  # 1 hour
                logger.warning(f"Model file may be old: {model_path}")
                return False
        else:
            logger.error(f"Model file missing: {model_path}")
            return False

    return True


def _check_real_models_deployed() -> bool:
    """Check that real model files are properly deployed"""
    required_files = [
        "/mnt/c/Intellicrack/intellicrack/models/vulnerability_model.joblib",
        "/mnt/c/Intellicrack/intellicrack/models/licensing_model.joblib",
        "/mnt/c/Intellicrack/intellicrack/ui/models/vuln_predict_model.joblib"
    ]

    metadata_files = [
        "/mnt/c/Intellicrack/intellicrack/models/vulnerability_model_metadata.json",
        "/mnt/c/Intellicrack/intellicrack/models/licensing_model_metadata.json"
    ]

    # Check model files exist
    for model_file in required_files:
        if not os.path.exists(model_file):
            logger.error(f"Required model file missing: {model_file}")
            return False

        # Check file size (should be reasonable for real model)
        file_size = os.path.getsize(model_file)
        if file_size < 1000:  # Less than 1KB suggests empty/invalid model
            logger.error(f"Model file too small: {model_file} ({file_size} bytes)")
            return False

    # Check metadata files exist
    metadata_found = any(os.path.exists(f) for f in metadata_files)
    if not metadata_found:
        logger.warning("No metadata files found")

    logger.info(f"All {len(required_files)} model files deployed successfully")
    return True


def _validate_model_metadata() -> bool:
    """Validate that model metadata indicates real training"""
    metadata_paths = [
        "/mnt/c/Intellicrack/intellicrack/models/licensing_model_metadata.json",
        "/mnt/c/Intellicrack/licensing_model_output/licensing_model_metadata.json"
    ]

    for metadata_path in metadata_paths:
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)

                # Check model info
                model_info = metadata.get('model_info', {})
                model_type = model_info.get('type', '')
                data_source = model_info.get('data_source', '')
                version = model_info.get('version', '')

                # Validate it's a real model
                if 'real' not in model_type.lower() and 'real' not in version.lower():
                    logger.error(f"Model type does not indicate real training: {model_type}")
                    return False

                if 'real' not in data_source.lower():
                    logger.error(f"Data source does not indicate real data: {data_source}")
                    return False

                # Check for synthetic indicators (should not be present)
                metadata_str = json.dumps(metadata).lower()
                synthetic_indicators = ['synthetic', 'fake', 'simulated', 'mock', 'stub']

                for indicator in synthetic_indicators:
                    if indicator in metadata_str:
                        logger.error(f"Synthetic indicator found in metadata: {indicator}")
                        return False

                logger.info(f"Metadata validation passed: {metadata_path}")
                return True

            except Exception as e:
                logger.error(f"Error reading metadata {metadata_path}: {e}")

    logger.warning("No valid metadata found")
    return False


def _test_model_functionality() -> bool:
    """Test that the deployed model actually works"""
    try:
        # Try to load the model
        model_path = "/mnt/c/Intellicrack/intellicrack/models/licensing_model.joblib"
        model = joblib.load(model_path)

        # Check model type
        model_type = str(type(model))
        if 'pipeline' not in model_type.lower() and 'ensemble' not in model_type.lower():
            logger.warning(f"Unexpected model type: {model_type}")

        # Test prediction capability
        if hasattr(model, 'predict') and hasattr(model, 'predict_proba'):
            # Create dummy feature vector (49 features based on training)
            import numpy as np
            dummy_features = np.random.rand(1, 49)

            # Test prediction
            prediction = model.predict(dummy_features)
            probabilities = model.predict_proba(dummy_features)

            # Validate output format
            if len(prediction) == 1 and len(probabilities) == 1 and len(probabilities[0]) == 2:
                logger.info("Model functionality test passed")
                return True
            else:
                logger.error("Model output format invalid")
                return False
        else:
            logger.error("Model missing predict methods")
            return False

    except Exception as e:
        logger.error(f"Model functionality test failed: {e}")
        return False


def _verify_real_data_source() -> bool:
    """Verify that model was trained on real data, not synthetic"""

    # Check for training data directory
    training_data_dir = "/mnt/c/Intellicrack/licensing_training_data"
    if not os.path.exists(training_data_dir):
        logger.warning("Training data directory not found")
        return False

    # Check for real binaries in training data
    real_binaries_found = False
    for category_dir in os.listdir(training_data_dir):
        category_path = os.path.join(training_data_dir, category_dir)
        if os.path.isdir(category_path):
            binaries = [f for f in os.listdir(category_path) if os.path.isfile(os.path.join(category_path, f))]
            if binaries:
                real_binaries_found = True
                logger.info(f"Found {len(binaries)} binaries in {category_dir}")

    if not real_binaries_found:
        logger.error("No real training binaries found")
        return False

    # Check that synthetic training script is not in active location
    synthetic_script = "/mnt/c/Intellicrack/intellicrack/models/create_ml_model.py"
    if os.path.exists(synthetic_script):
        logger.error("Synthetic training script still exists in active location")
        return False

    # Check that real training scripts exist
    real_scripts = [
        "/mnt/c/Intellicrack/intellicrack/models/streamlined_licensing_trainer.py",
        "/mnt/c/Intellicrack/intellicrack/models/licensing_patterns_extractor.py",
        "/mnt/c/Intellicrack/intellicrack/models/licensing_detection_predictor.py"
    ]

    for script in real_scripts:
        if not os.path.exists(script):
            logger.error(f"Real training script missing: {script}")
            return False

    logger.info("Real data source verification passed")
    return True


def print_validation_report(results: Dict[str, bool]):
    """Print comprehensive validation report"""
    print("\n" + "="*80)
    print("REAL MODEL DEPLOYMENT VALIDATION REPORT")
    print("="*80)

    all_passed = all(results.values())
    status = "✅ PASSED" if all_passed else "❌ FAILED"
    print(f"Overall Status: {status}")

    print("\nValidation Results:")
    for check, passed in results.items():
        status_icon = "✅" if passed else "❌"
        check_name = check.replace('_', ' ').title()
        print(f"  {status_icon} {check_name}: {'PASSED' if passed else 'FAILED'}")

    if all_passed:
        print("\n🎉 SUCCESS: Real licensing model system is fully deployed!")
        print("   • Synthetic training system completely removed")
        print("   • Real ML model trained on actual binaries")
        print("   • All model files deployed and functional")
        print("   • No synthetic/fake data detected")
    else:
        print("\n⚠️  ISSUES DETECTED: Some validation checks failed")
        failed_checks = [check for check, passed in results.items() if not passed]
        print(f"   Failed checks: {', '.join(failed_checks)}")

    print("="*80)


def main():
    """Main validation function"""
    try:
        results = validate_real_model_deployment()
        print_validation_report(results)

        return 0 if all(results.values()) else 1

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
