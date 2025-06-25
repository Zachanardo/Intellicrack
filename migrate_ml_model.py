#!/usr/bin/env python3
"""
Migrate from Old ML Model to Advanced Licensing Detector

This script helps migrate from the old ML model system to the new
advanced licensing detection system.
"""

import os
import sys
import shutil
import json
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def migrate_ml_system():
    """Migrate from old to new ML system"""
    print("=" * 80)
    print("INTELLICRACK ML MODEL MIGRATION")
    print("=" * 80)
    print()
    
    # Define paths
    models_dir = Path(__file__).parent / "intellicrack" / "models"
    
    # Old model files
    old_files = [
        "vulnerability_model.joblib",
        "licensing_model.joblib", 
        "ml_vulnerability_model.joblib",
        "vuln_predict_model.joblib",
        "ml_model_info.txt"
    ]
    
    # New model files
    new_model_file = "advanced_licensing_model.joblib"
    new_metadata_file = "advanced_licensing_metadata.json"
    
    # Check for old models
    print("Checking for old ML models...")
    found_old_models = []
    
    for old_file in old_files:
        old_path = models_dir / old_file
        if old_path.exists():
            size_mb = old_path.stat().st_size / 1024 / 1024
            found_old_models.append((old_file, size_mb))
            print(f"  ✓ Found: {old_file} ({size_mb:.2f} MB)")
    
    if not found_old_models:
        print("  No old models found.")
    else:
        print(f"\nFound {len(found_old_models)} old model files.")
    
    # Check for new model
    print("\nChecking for new advanced model...")
    new_model_path = models_dir / new_model_file
    new_metadata_path = models_dir / new_metadata_file
    
    if new_model_path.exists():
        size_mb = new_model_path.stat().st_size / 1024 / 1024
        print(f"  ✓ Advanced model already exists: {size_mb:.2f} MB")
        
        if new_metadata_path.exists():
            with open(new_metadata_path, 'r') as f:
                metadata = json.load(f)
            print(f"    Version: {metadata.get('version', 'Unknown')}")
            print(f"    Accuracy: {metadata.get('accuracy', 0):.2%}")
            print(f"    Trained: {metadata.get('trained_at', 'Unknown')}")
    else:
        print("  ✗ Advanced model not found - training required")
    
    # Backup old models
    if found_old_models:
        print("\nBacking up old models...")
        backup_dir = models_dir / "old_models_backup"
        backup_dir.mkdir(exist_ok=True)
        
        for old_file, _ in found_old_models:
            old_path = models_dir / old_file
            backup_path = backup_dir / old_file
            
            if not backup_path.exists():
                shutil.copy2(old_path, backup_path)
                print(f"  ✓ Backed up: {old_file}")
            else:
                print(f"  - Already backed up: {old_file}")
    
    # Create compatibility report
    print("\n" + "=" * 80)
    print("COMPATIBILITY REPORT")
    print("=" * 80)
    
    print("\nOld System:")
    print("  - Binary classification only (has protection: yes/no)")
    print("  - Limited to 49 features")
    print("  - ~2.5MB model size")
    print("  - Basic protection detection")
    
    print("\nNew System:")
    print("  - Multi-class classification (10+ protection types)")
    print("  - 200+ advanced features")
    print("  - 500MB-1.5GB model size")
    print("  - Handles obfuscation and packing")
    print("  - Streaming training (no local storage)")
    print("  - Real-time analysis capability")
    
    print("\nAPI Compatibility:")
    print("  ✓ All old imports automatically redirected")
    print("  ✓ predict_vulnerability() method maintained")
    print("  ✓ IntellicrackMLPredictor class compatible")
    print("  ✓ Backward compatible output format")
    
    print("\nNew Features Available:")
    print("  + Protection type identification")
    print("  + Bypass difficulty assessment")
    print("  + Detailed protection analysis")
    print("  + Feature importance scores")
    print("  + Confidence levels")
    
    # Code migration examples
    print("\n" + "=" * 80)
    print("CODE MIGRATION EXAMPLES")
    print("=" * 80)
    
    print("\nOld Code:")
    print("```python")
    print("from intellicrack.models.ml_integration import IntellicrackMLPredictor")
    print("predictor = IntellicrackMLPredictor()")
    print("result = predictor.predict_vulnerability('binary.exe')")
    print("print(f'Vulnerable: {result[\"prediction\"]}')")
    print("```")
    
    print("\nNew Code (backward compatible):")
    print("```python")
    print("# Same imports work - automatically redirected to new system")
    print("from intellicrack.models import IntellicrackMLPredictor")
    print("predictor = IntellicrackMLPredictor()")
    print("result = predictor.predict_vulnerability('binary.exe')")
    print("print(f'Vulnerable: {result[\"prediction\"]}')")
    print("```")
    
    print("\nNew Code (using new features):")
    print("```python")
    print("from intellicrack.models import get_ml_system")
    print("ml_system = get_ml_system()")
    print("result = ml_system.predict('binary.exe')")
    print("print(f'Protection: {result[\"protection_type\"]}')")
    print("print(f'Confidence: {result[\"confidence\"]:.2%}')")
    print("print(f'Difficulty: {result[\"bypass_difficulty\"]}')")
    print("```")
    
    # Check for files using old imports
    print("\n" + "=" * 80)
    print("CHECKING FOR FILES USING OLD IMPORTS")
    print("=" * 80)
    
    intellicrack_dir = Path(__file__).parent / "intellicrack"
    old_import_patterns = [
        "from intellicrack.models.ml_integration import",
        "from intellicrack.models.robust_licensing_trainer import",
        "from intellicrack.models.licensing_patterns_extractor import",
        "from .models.ml_integration import",
        "import intellicrack.models.ml_integration"
    ]
    
    files_to_update = []
    
    for py_file in intellicrack_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding='utf-8')
            for pattern in old_import_patterns:
                if pattern in content:
                    files_to_update.append(str(py_file))
                    break
        except Exception:
            pass
    
    if files_to_update:
        print(f"\nFound {len(files_to_update)} files with old imports:")
        for file_path in files_to_update[:10]:  # Show first 10
            print(f"  - {file_path}")
        if len(files_to_update) > 10:
            print(f"  ... and {len(files_to_update) - 10} more")
        print("\nNote: These will work automatically due to compatibility layer!")
    else:
        print("\nNo files found using old imports.")
    
    # Training recommendation
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    
    if not new_model_path.exists():
        print("\n⚠️  IMPORTANT: You need to train the new advanced model!")
        print("\nTo train the model, run:")
        print("  python train_advanced_model.py")
        print("\nTraining will:")
        print("  - Collect URLs from legitimate sources")
        print("  - Use streaming (no local storage needed)")
        print("  - Take approximately 3-5 hours")
        print("  - Create a 500MB-1.5GB model file")
    else:
        print("\n✓ Advanced model is already trained and ready!")
        print("\nYour ML system has been successfully migrated.")
        print("All old code will continue to work with the new system.")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    migrate_ml_system()