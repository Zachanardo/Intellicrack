# Protection Classifier Model

This directory contains the trained machine learning model for classifying software protection schemes.

## Model Architecture

- **Algorithm**: Random Forest Classifier (200 trees)
- **Features**: 44 engineered features extracted from PE binaries
- **Classes**: VMProtect, Themida, Enigma, Obsidium, ASProtect, Armadillo, UPX, None
- **Framework**: scikit-learn 1.7.2

## Feature Categories

### Entropy Features (7)
- Overall entropy, section-specific entropy (text, data, rdata)
- Max/min/average section entropy
- High entropy section count

### PE Structure Features (4)
- TLS callbacks presence
- Overlay size
- Resource section size
- Entry point section index

### Section Features (4)
- Section count
- Executable section count
- Unusual section names count
- Virtual-to-raw size ratio

### Import Table Features (4)
- Total import count
- Unique DLL count
- Suspicious import count
- Packed import table indicator

### Signature Features (7)
- Binary presence of known protector strings (VMProtect, Themida, Enigma, etc.)

### Opcode Features (16)
- Frequency distribution of instruction opcodes in executable sections

### Code Complexity Features (2)
- Cyclomatic complexity estimate
- Unusual section naming patterns

## Files

- `model.pkl`: Trained Random Forest model
- `scaler.pkl`: StandardScaler for feature normalization
- `encoder.pkl`: Label encoder for class names
- `metadata.json`: Model metadata and configuration
- `training_results.json`: Training metrics and performance data

## Performance

Expected performance on test set:
- **Accuracy**: >85%
- **Cross-validation**: >80% mean accuracy

## Usage

### Training a New Model

```bash
pixi run python -m intellicrack.tools.train_classifier --synthetic --samples-per-class 150
```

With real data:
```bash
pixi run python -m intellicrack.tools.train_classifier --data-dir /path/to/labeled/samples
```

### Classifying a Binary

```bash
pixi run python -m intellicrack.tools.classify_protection target.exe
```

### Python API

```python
from intellicrack.core.ml.protection_classifier import ProtectionClassifier

classifier = ProtectionClassifier()
result = classifier.predict('target.exe')

print(f"Protection: {result.primary_protection}")
print(f"Confidence: {result.confidence:.2%}")
```

## Model Versioning

Current version: 1.0.0

## Training Data Requirements

For optimal performance, training data should include:
- At least 50 samples per protection class
- Diverse software types (applications, games, utilities)
- Multiple versions of each protector
- Balanced class distribution

## Retraining

The model should be retrained when:
- New protector versions are released
- Classification accuracy drops below 80%
- New protection schemes need to be added
- More training data becomes available

## Feature Importance

Top features for classification (example):
1. `signature_vmprotect`: Direct VMProtect string detection
2. `overall_entropy`: Overall file entropy
3. `text_entropy`: Code section entropy
4. `unusual_section_names`: Non-standard section naming
5. `high_entropy_section_count`: Number of highly entropic sections

## License

Copyright (C) 2025 Zachary Flint

This model is part of Intellicrack and licensed under GPLv3.
