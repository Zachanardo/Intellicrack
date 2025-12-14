# ML Integration Production Tests

## Overview

Comprehensive production-ready test suite for Intellicrack's machine learning integration system. These tests validate real ML operations on actual Windows binaries with zero mocks or stubs.

## Test File

**Location:** `D:\Intellicrack\tests\ml\test_ml_integration_production.py`

**Total Tests:** 54 comprehensive production tests

## Test Coverage Areas

### 1. ML Integration Initialization (5 tests)

- ML integration disables correctly without trained model
- ML integration enables with trained model
- Incremental learning component initialization
- Sample database initialization
- Classifier loading from persisted model files

**Key Validation:** Tests ensure ML components initialize correctly and gracefully handle missing models.

### 2. Binary Classification (10 tests)

- Real binary classification with valid structured results
- Alternative predictions inclusion
- Multiple binary differentiation
- Confidence level categorization (high, medium, low, very_low)
- Reliable flag accuracy
- Low confidence warnings
- Classification consistency

**Key Validation:** Classification produces genuine ML predictions on real Windows executables with proper confidence scoring.

### 3. Feature Extraction (9 tests)

- Feature extraction from real Windows binaries
- Correct feature vector dimensionality
- Entropy feature extraction and validation
- PE section feature extraction
- Import table feature extraction
- Protection signature detection
- Opcode frequency analysis
- Feature extraction consistency
- Binary differentiation via features

**Key Validation:** Feature extractor produces valid, consistent feature vectors from real PE binaries.

### 4. Model Training and Prediction (5 tests)

- Classifier training on real binary features
- Prediction generation from trained models
- Top-N alternative predictions
- Model persistence (save/load)
- Cross-validation accuracy metrics

**Key Validation:** ML models train successfully on real data and produce reproducible predictions.

### 5. Incremental Learning (4 tests)

- Sample addition to learning buffer
- Buffer statistics accuracy
- Sample quality evaluation
- Uncertain prediction identification for active learning

**Key Validation:** Incremental learning system buffers samples and identifies candidates for manual labeling.

### 6. Sample Database (6 tests)

- Sample addition with metadata tracking
- Duplicate prevention
- Higher confidence label updates
- Protection type filtering
- Database statistics
- Training data extraction

**Key Validation:** Sample database correctly stores, organizes, and retrieves training samples.

### 7. Complete ML Workflows (5 tests)

- End-to-end ML analysis workflow
- Verified sample addition across components
- Learning statistics aggregation
- Protection-specific tool recommendations
- Generic tool recommendations for unknown protections

**Key Validation:** Complete workflows integrate all ML components correctly.

### 8. Performance Benchmarks (3 tests)

- Feature extraction performance (< 5 seconds)
- Prediction performance (< 6 seconds)
- Batch classification throughput (< 10 seconds average)

**Key Validation:** ML operations complete within production-acceptable timeframes.

### 9. Error Handling (4 tests)

- Nonexistent file handling
- Disabled ML integration behavior
- Insufficient training samples
- Invalid PE file processing
- Model prediction without trained model

**Key Validation:** System handles error conditions gracefully without crashes.

### 10. Feature Importance (2 tests)

- Feature importance ranking
- Feature importance normalization

**Key Validation:** ML model provides interpretable feature importance scores.

### 11. Active Learning (1 test)

- Uncertain sample identification for manual review

**Key Validation:** Active learning identifies samples requiring human verification.

## Real Binary Usage

All tests use **actual Windows system binaries**:

- `C:\Windows\System32\notepad.exe`
- `C:\Windows\System32\calc.exe`
- `C:\Windows\System32\kernel32.dll`
- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Zero Mocks Policy

**NO mocks, stubs, or MagicMock instances** - All tests:

- Extract features from real PE binaries
- Train actual ML models with scikit-learn
- Generate genuine predictions
- Persist and load real model files
- Validate actual ML pipeline operations

## Test Execution

### Run All Tests

```bash
pixi run pytest tests/ml/test_ml_integration_production.py -v
```

### Run Without Coverage

```bash
pixi run pytest tests/ml/test_ml_integration_production.py --no-cov -v
```

### Run Specific Test Class

```bash
pixi run pytest tests/ml/test_ml_integration_production.py::TestFeatureExtraction -v
```

### Run Performance Tests Only

```bash
pixi run pytest tests/ml/test_ml_integration_production.py::TestPerformanceBenchmarks -v
```

## Success Criteria

Tests validate genuine ML capabilities:

✅ **Feature Extraction:** Extracts valid feature vectors from real PE binaries
✅ **Model Training:** Successfully trains RandomForest classifiers on binary features
✅ **Prediction:** Generates protection scheme predictions with confidence scores
✅ **Persistence:** Saves and loads trained models from disk
✅ **Incremental Learning:** Buffers samples and triggers retraining
✅ **Database Management:** Stores and retrieves training samples
✅ **Performance:** Operations complete within production timeframes
✅ **Error Handling:** Gracefully handles invalid inputs and edge cases

## Test Quality Standards

- **Complete Type Annotations:** All test functions and variables fully typed
- **Descriptive Names:** Test names clearly indicate scenario and expected outcome
- **Real Operations:** Every test validates genuine ML functionality
- **No Placeholders:** No `assert result is not None` - all assertions verify real capability
- **Production Ready:** Tests could run in CI/CD without modification

## Dependencies

Required packages (managed via pixi):

- pytest
- pytest-benchmark
- numpy
- scikit-learn
- joblib

## Coverage Impact

These tests significantly improve coverage for:

- `intellicrack/core/ml/ml_integration.py`
- `intellicrack/core/ml/feature_extraction.py`
- `intellicrack/core/ml/protection_classifier.py`
- `intellicrack/core/ml/incremental_learner.py`
- `intellicrack/core/ml/sample_database.py`

## Maintenance Notes

1. **Binary Availability:** Tests skip gracefully if Windows system binaries unavailable
2. **Temporary Directories:** All model and database files use temp directories with cleanup
3. **Fixture Scoping:** Module-scoped fixtures for expensive operations (binary loading)
4. **Deterministic:** Feature extraction is deterministic - same binary produces same features

## Future Enhancements

Potential additions:

- Property-based testing with Hypothesis for algorithm validation
- Adversarial testing with malformed PE structures
- Large-scale performance benchmarks with 100+ binaries
- Distributed training validation
- Model versioning compatibility tests
- Real protected binary samples (VMProtect, Themida, etc.)
