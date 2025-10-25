"""Demonstration of ML-based protection classification.

This script demonstrates the complete ML classification pipeline including:
- Training a model with synthetic data
- Classifying binaries
- Incremental learning
- Sample database management

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import struct
import sys
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def create_test_binary(output_path: Path, protection_type: str) -> None:
    """Create a synthetic test binary with protection characteristics."""
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 128)

    coff_header = bytearray(20)
    coff_header[0:2] = struct.pack('<H', 0x014c)
    coff_header[2:4] = struct.pack('<H', 2)
    coff_header[16:18] = struct.pack('<H', 224)

    optional_header = bytearray(224)
    optional_header[0:2] = struct.pack('<H', 0x010b)

    section_table = bytearray()

    if protection_type == 'VMProtect':
        section1 = bytearray(40)
        section1[0:6] = b'.vmp0\x00'
        section1[8:12] = struct.pack('<I', 0x2000)
        section1[12:16] = struct.pack('<I', 0x1000)
        section1[16:20] = struct.pack('<I', 0x2000)
        section1[20:24] = struct.pack('<I', 0x400)
        section1[36:40] = struct.pack('<I', 0x60000020)
        section_table.extend(section1)

        high_entropy = bytes(np.random.randint(0, 256, size=8192, dtype=np.uint8))
        code = b'VMProtect signatures here\x00' * 50 + high_entropy

    elif protection_type == 'Themida':
        section1 = bytearray(40)
        section1[0:8] = b'.Themida'
        section1[8:12] = struct.pack('<I', 0x2000)
        section1[12:16] = struct.pack('<I', 0x1000)
        section1[16:20] = struct.pack('<I', 0x2000)
        section1[20:24] = struct.pack('<I', 0x400)
        section1[36:40] = struct.pack('<I', 0x60000020)
        section_table.extend(section1)

        high_entropy = bytes(np.random.randint(0, 256, size=8192, dtype=np.uint8))
        code = b'Themida\x00WinLicense\x00' * 50 + high_entropy

    elif protection_type == 'UPX':
        section1 = bytearray(40)
        section1[0:5] = b'UPX0\x00'
        section1[8:12] = struct.pack('<I', 0x1000)
        section1[12:16] = struct.pack('<I', 0x1000)
        section1[16:20] = struct.pack('<I', 0x1000)
        section1[20:24] = struct.pack('<I', 0x400)
        section1[36:40] = struct.pack('<I', 0x60000020)
        section_table.extend(section1)

        code = b'UPX!' * 100 + b'\x00' * 3000

    else:
        section1 = bytearray(40)
        section1[0:6] = b'.text\x00'
        section1[8:12] = struct.pack('<I', 0x1000)
        section1[12:16] = struct.pack('<I', 0x1000)
        section1[16:20] = struct.pack('<I', 0x1000)
        section1[20:24] = struct.pack('<I', 0x400)
        section1[36:40] = struct.pack('<I', 0x60000020)
        section_table.extend(section1)

        code = b'\x55\x8B\xEC\x83\xEC\x40' * 500

    pe_binary = (
        dos_header + b'\x00' * 64 + b'PE\x00\x00' +
        coff_header + optional_header + section_table +
        code
    )

    with open(output_path, 'wb') as f:
        f.write(pe_binary)

    logger.info("Created test binary: %s (%s)", output_path, protection_type)


def demo_training():
    """Demonstrate model training."""
    logger.info("\n" + "=" * 60)
    logger.info("DEMO 1: Training ML Classifier")
    logger.info("=" * 60)

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        'train_classifier',
        'D:/Intellicrack/intellicrack/tools/train_classifier.py'
    )
    train_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(train_module)

    spec = importlib.util.spec_from_file_location(
        'protection_classifier',
        'D:/Intellicrack/intellicrack/core/ml/protection_classifier.py'
    )
    classifier_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(classifier_module)

    logger.info("Generating synthetic training data...")
    X, y = train_module.generate_synthetic_data(samples_per_class=100)

    logger.info("Training Random Forest classifier...")
    classifier = classifier_module.ProtectionClassifier()

    results = classifier.train(
        X=X,
        y=y,
        n_estimators=100,
        cross_validate=True
    )

    logger.info("\nTraining Results:")
    logger.info("  Train accuracy: %.2f%%", results['train_accuracy'] * 100)
    logger.info("  Test accuracy: %.2f%%", results['test_accuracy'] * 100)
    logger.info("  CV accuracy: %.2f%% (+/- %.2f%%)",
                results['cv_mean_accuracy'] * 100,
                results['cv_std_accuracy'] * 200)

    logger.info("\nTop 5 important features:")
    for feat, importance in results['top_features'][:5]:
        logger.info("  %s: %.4f", feat, importance)

    return classifier


def demo_classification(classifier):
    """Demonstrate binary classification."""
    logger.info("\n" + "=" * 60)
    logger.info("DEMO 2: Binary Classification")
    logger.info("=" * 60)

    test_dir = Path("test_binaries_ml_demo")
    test_dir.mkdir(exist_ok=True)

    test_cases = [
        ('vmprotect_test.exe', 'VMProtect'),
        ('themida_test.exe', 'Themida'),
        ('upx_test.exe', 'UPX'),
        ('unprotected.exe', 'None'),
    ]

    for filename, protection in test_cases:
        binary_path = test_dir / filename
        create_test_binary(binary_path, protection)

        result = classifier.predict(binary_path)

        logger.info("\nBinary: %s", filename)
        logger.info("  Expected: %s", protection)
        logger.info("  Predicted: %s (%.2f%% confidence)",
                    result.primary_protection,
                    result.confidence * 100)
        logger.info("  Alternatives:")
        for alt_prot, alt_conf in result.top_predictions[:3]:
            logger.info("    %s: %.2f%%", alt_prot, alt_conf * 100)

    import shutil
    shutil.rmtree(test_dir)


def demo_incremental_learning(classifier):
    """Demonstrate incremental learning."""
    logger.info("\n" + "=" * 60)
    logger.info("DEMO 3: Incremental Learning")
    logger.info("=" * 60)

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        'incremental_learner',
        'D:/Intellicrack/intellicrack/core/ml/incremental_learner.py'
    )
    learner_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(learner_module)

    learner = learner_module.IncrementalLearner(
        classifier=classifier,
        auto_retrain=False
    )

    test_dir = Path("incremental_test")
    test_dir.mkdir(exist_ok=True)

    logger.info("Adding new samples to learning buffer...")

    for i in range(10):
        binary_path = test_dir / f"sample_{i}.exe"
        protection = ['VMProtect', 'Themida', 'UPX'][i % 3]
        create_test_binary(binary_path, protection)

        learner.add_sample(
            binary_path=binary_path,
            protection_type=protection,
            confidence=0.9,
            source='manual'
        )

    stats = learner.get_buffer_statistics()

    logger.info("\nBuffer statistics:")
    logger.info("  Total samples: %d", stats['size'])
    logger.info("  Class distribution:")
    for prot, count in stats['classes'].items():
        logger.info("    %s: %d", prot, count)
    logger.info("  Average confidence: %.2f", stats['avg_confidence'])

    import shutil
    shutil.rmtree(test_dir)


def demo_sample_database():
    """Demonstrate sample database management."""
    logger.info("\n" + "=" * 60)
    logger.info("DEMO 4: Sample Database Management")
    logger.info("=" * 60)

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        'sample_database',
        'D:/Intellicrack/intellicrack/core/ml/sample_database.py'
    )
    db_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(db_module)

    db_path = Path("demo_sample_db")
    database = db_module.SampleDatabase(database_path=db_path)

    test_dir = Path("db_test_binaries")
    test_dir.mkdir(exist_ok=True)

    logger.info("Adding samples to database...")

    for i in range(15):
        binary_path = test_dir / f"db_sample_{i}.exe"
        protection = ['VMProtect', 'Themida', 'Enigma'][i % 3]
        create_test_binary(binary_path, protection)

        database.add_sample(
            binary_path=binary_path,
            protection_type=protection,
            confidence=0.85,
            verified=(i % 2 == 0),
            notes=f"Test sample {i}"
        )

    stats = database.get_statistics()

    logger.info("\nDatabase statistics:")
    logger.info("  Total samples: %d", stats['total_samples'])
    logger.info("  Verified samples: %d", stats['verified_samples'])
    logger.info("  Total size: %.2f MB", stats['total_size_mb'])
    logger.info("\n  Protection types:")
    for prot, count in stats['protection_types'].items():
        logger.info("    %s: %d", prot, count)

    import shutil
    shutil.rmtree(test_dir)
    shutil.rmtree(db_path)


def main():
    """Run all demonstrations."""
    try:
        logger.info("ML-Based Protection Classification Demo")
        logger.info("=" * 60)

        classifier = demo_training()

        demo_classification(classifier)

        demo_incremental_learning(classifier)

        demo_sample_database()

        logger.info("\n" + "=" * 60)
        logger.info("All demonstrations completed successfully!")
        logger.info("=" * 60)

        return 0

    except Exception as e:
        logger.error("Demo failed: %s", e, exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
