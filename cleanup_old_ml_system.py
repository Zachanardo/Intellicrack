#!/usr/bin/env python3
"""
Cleanup Old ML System Files

This script safely removes old ML system files that have been replaced
by the new advanced licensing detection system.
"""

import os
import shutil
from pathlib import Path
from datetime import datetime


def cleanup_old_ml_system():
    """Remove old ML system files after backing them up"""
    print("=" * 80)
    print("INTELLICRACK ML SYSTEM CLEANUP")
    print("=" * 80)
    print()
    
    # Define old files to remove
    base_dir = Path(__file__).parent
    models_dir = base_dir / "intellicrack" / "models"
    
    old_files = {
        "Python files (replaced by new system)": [
            models_dir / "ml_integration.py",
            models_dir / "robust_licensing_trainer.py",
            models_dir / "licensing_patterns_extractor.py",
            models_dir / "focused_licensing_collector.py",
        ],
        "Old model files": [
            models_dir / "vulnerability_model.joblib",
            models_dir / "licensing_model.joblib",
            models_dir / "ml_vulnerability_model.joblib",
            models_dir / "vuln_predict_model.joblib",
            models_dir / "ml_model_info.txt",
            models_dir / "vulnerability_model_metadata.json",
            models_dir / "create_ml_model.py",
        ],
        "Backup directories": [
            base_dir / "backup_synthetic_models",
            models_dir / "old_models_backup",
            models_dir / "radare2",  # Old licensing detector
        ],
        "Old output directories": [
            base_dir / "licensing_model_output",
            base_dir / "robust_model_output",
        ],
        "UI model files": [
            base_dir / "intellicrack" / "ui" / "models" / "vuln_predict_model.joblib",
        ]
    }
    
    # Create backup directory
    backup_dir = base_dir / "old_ml_system_backup" / datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Backup directory: {backup_dir}")
    print()
    
    # Process each category
    total_removed = 0
    total_size = 0
    
    for category, files in old_files.items():
        print(f"\n{category}:")
        print("-" * 60)
        
        for file_path in files:
            if file_path.exists():
                # Calculate size
                if file_path.is_file():
                    size = file_path.stat().st_size / 1024 / 1024  # MB
                    total_size += size
                else:
                    # Directory size
                    size = sum(f.stat().st_size for f in file_path.rglob('*') if f.is_file()) / 1024 / 1024
                    total_size += size
                
                # Create backup
                relative_path = file_path.relative_to(base_dir)
                backup_path = backup_dir / relative_path
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    if file_path.is_file():
                        shutil.copy2(file_path, backup_path)
                        print(f"  ✓ Backed up: {relative_path} ({size:.2f} MB)")
                    else:
                        shutil.copytree(file_path, backup_path)
                        print(f"  ✓ Backed up directory: {relative_path} ({size:.2f} MB)")
                    
                    # Remove original
                    if file_path.is_file():
                        file_path.unlink()
                    else:
                        shutil.rmtree(file_path)
                    
                    print(f"  ✓ Removed: {relative_path}")
                    total_removed += 1
                    
                except Exception as e:
                    print(f"  ✗ Error processing {relative_path}: {e}")
            else:
                print(f"  - Not found: {file_path.name}")
    
    # Clean up __pycache__ directories
    print("\n\nCleaning __pycache__ directories:")
    print("-" * 60)
    
    pycache_dirs = list(models_dir.rglob("__pycache__"))
    for pycache in pycache_dirs:
        try:
            shutil.rmtree(pycache)
            print(f"  ✓ Removed: {pycache.relative_to(base_dir)}")
            total_removed += 1
        except Exception as e:
            print(f"  ✗ Error removing {pycache}: {e}")
    
    # Summary
    print("\n" + "=" * 80)
    print("CLEANUP SUMMARY")
    print("=" * 80)
    print(f"Total files/directories removed: {total_removed}")
    print(f"Total space freed: {total_size:.2f} MB")
    print(f"Backup location: {backup_dir}")
    
    # Verify new system
    print("\nVerifying new ML system...")
    try:
        from intellicrack.models import get_ml_system, get_current_model_info
        ml_system = get_ml_system()
        model_info = get_current_model_info()
        
        print(f"  ✓ New ML system type: {model_info['type']}")
        print(f"  ✓ Model loaded: {model_info['loaded']}")
        print(f"  ✓ Model exists: {model_info['exists']}")
        
        if model_info['exists']:
            print(f"  ✓ Model size: {model_info['size_mb']:.2f} MB")
        else:
            print("  ⚠ Note: New model not yet trained")
            print("     Run 'python train_advanced_model.py' to train")
        
    except Exception as e:
        print(f"  ✗ Error verifying new system: {e}")
    
    print("\n✅ Cleanup complete!")
    print("\nNext steps:")
    print("1. If new model not trained: python train_advanced_model.py")
    print("2. Test the system: python test_advanced_ml.py")
    print("3. Run Intellicrack to verify everything works")
    
    # Option to restore
    print(f"\nTo restore old files, copy from: {backup_dir}")


def main():
    """Main entry point"""
    print("This will remove old ML system files and create a backup.")
    response = input("\nProceed with cleanup? (y/N): ")
    
    if response.lower() == 'y':
        cleanup_old_ml_system()
    else:
        print("Cleanup cancelled.")


if __name__ == "__main__":
    main()