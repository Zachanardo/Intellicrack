"""Simple standalone ML classification demonstration.

This demonstrates the ML classifier without full package dependencies.

Copyright (C) 2025 Zachary Flint
"""

import logging
import struct
import sys
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def create_test_binary(path: Path, protection: str):
    """Create minimal test binary."""
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[60:64] = struct.pack('<I', 128)

    section = bytearray(40)
    if protection == 'VMProtect':
        section[0:6] = b'.vmp0\x00'
        code = b'VMProtect' * 100 + bytes(np.random.randint(200, 256, 2000, dtype=np.uint8))
    elif protection == 'UPX':
        section[0:5] = b'UPX0\x00'
        code = b'UPX!' * 200
    else:
        section[0:6] = b'.text\x00'
        code = b'\x55\x8B\xEC' * 300

    pe = dos_header + b'\x00' * 64 + b'PE\x00\x00' + b'\x00' * 244 + section + code

    path.write_bytes(pe)
    return path


def demo():
    """Run demonstration."""
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from intellicrack.core.ml.protection_classifier import ProtectionClassifier
    from intellicrack.tools.train_classifier import generate_synthetic_data

    logger.info("=" * 60)
    logger.info("ML Protection Classification Demo")
    logger.info("=" * 60)

    logger.info("\n1. Generating synthetic training data...")
    X, y = generate_synthetic_data(samples_per_class=50)
    logger.info(f"   Generated {len(X)} samples with {X.shape[1]} features")

    logger.info("\n2. Training Random Forest classifier...")
    classifier = ProtectionClassifier()
    results = classifier.train(X, y, n_estimators=50, cross_validate=False)

    logger.info(f"   Train accuracy: {results['train_accuracy']:.1%}")
    logger.info(f"   Test accuracy: {results['test_accuracy']:.1%}")

    logger.info("\n3. Testing on synthetic binaries...")
    test_dir = Path("temp_ml_test")
    test_dir.mkdir(exist_ok=True)

    for prot in ['VMProtect', 'UPX', 'None']:
        binary = create_test_binary(test_dir / f"{prot}.exe", prot)
        result = classifier.predict(binary)

        logger.info(f"\n   {prot}.exe:")
        logger.info(f"     Predicted: {result.primary_protection} ({result.confidence:.1%})")

    test_dir.chmod(0o777)
    import shutil
    shutil.rmtree(test_dir, ignore_errors=True)

    logger.info("\n" + "=" * 60)
    logger.info("Demo completed successfully!")
    logger.info("=" * 60)


if __name__ == '__main__':
    try:
        demo()
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        sys.exit(1)
