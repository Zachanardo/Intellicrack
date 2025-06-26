#!/usr/bin/env python3
"""
Train Minimal ML Model for Immediate Use

Creates a basic but functional model with synthetic data.
"""

import sys
import os
import numpy as np
import json
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from intellicrack.models.advanced_licensing_detector import AdvancedLicensingDetector
from intellicrack.models.protection_knowledge_base import ProtectionKnowledgeBase

print("=" * 80)
print("INTELLICRACK MINIMAL MODEL TRAINING")
print("=" * 80)
print()

# Create detector
detector = AdvancedLicensingDetector()

# Generate comprehensive synthetic training data
print("Generating synthetic training data...")

n_samples_per_class = 50
n_features = 200
X = []
y = []

# Use actual protection scheme names from knowledge base
kb = ProtectionKnowledgeBase()
protection_types = [scheme.name for scheme in list(kb.protection_schemes.values())[:10]]  # Use first 10 for training

print(f"Training for {len(protection_types)} protection types:")
for pt in protection_types:
    print(f"  - {pt}")

# Generate features for each protection type
for protection_idx, protection_type in enumerate(protection_types):
    for _ in range(n_samples_per_class):
        # Base random features
        features = np.random.rand(n_features) * 0.1
        
        # Add protection-specific patterns
        if protection_type == "sentinel_hasp":
            features[10:20] = np.random.rand(10) * 0.8 + 0.2
            features[150:160] = np.random.rand(10) * 0.7 + 0.3
        elif protection_type == "flexlm":
            features[30:40] = np.random.rand(10) * 0.7 + 0.3
            features[170:180] = np.random.rand(10) * 0.6 + 0.4
        elif protection_type == "codemeter":
            features[50:60] = np.random.rand(10) * 0.9 + 0.1
        elif protection_type == "winlicense":
            features[70:80] = np.random.rand(10) * 0.8 + 0.2
            features[90:100] = np.random.rand(10) * 0.7 + 0.3
        elif protection_type == "vmprotect":
            features[110:120] = np.random.rand(10) * 0.85 + 0.15
        elif protection_type == "steam_ceg":
            features[130:140] = np.random.rand(10) * 0.75 + 0.25
        elif protection_type == "denuvo":
            features[0:10] = np.random.rand(10) * 0.9 + 0.1
            features[190:200] = np.random.rand(10) * 0.8 + 0.2
        
        # Add some noise
        features += np.random.normal(0, 0.05, n_features)
        features = np.clip(features, 0, 1)
        
        X.append(features)
        y.append(protection_type)

# Add "none" class (no protection)
for _ in range(n_samples_per_class):
    features = np.random.rand(n_features) * 0.2  # Lower values for no protection
    X.append(features)
    y.append("none")

X = np.array(X)
y = np.array(y)

print(f"\nGenerated {len(X)} training samples")
print(f"Feature dimensions: {X.shape}")

# Set feature names and prepare for training
detector.feature_names = [f"feature_{i}" for i in range(n_features)]

# Split data for training
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Encode string labels to integers
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

X_train, X_val, y_train, y_val = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# Set internal training data
detector.X_train = X_train
detector.y_train = y_train
detector.label_encoder = label_encoder
detector.protection_types = list(label_encoder.classes_)

# Train the model using internal method
print("\nTraining model...")
training_stats = detector._train_final_models()

print("\nTraining complete!")
print(f"  - Accuracy: {training_stats.get('accuracy', 0):.2%}")
print(f"  - Classes: {training_stats.get('classes', 0)}")
print(f"  - Features: {training_stats.get('features', 0)}")

# Save the model
print("\nSaving model...")
if detector.save_model():
    model_path = Path(detector.model_path)
    metadata_path = Path(detector.metadata_path)
    
    if model_path.exists():
        print(f"Model saved to: {model_path}")
        print(f"Model size: {model_path.stat().st_size / 1024 / 1024:.2f} MB")
    
    if metadata_path.exists():
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        print(f"Metadata saved with {len(metadata.get('protection_types', []))} protection types")
else:
    print("Failed to save model")

print("\n" + "=" * 80)
print("MINIMAL MODEL TRAINING COMPLETE")
print("=" * 80)
print("\nThe model is now ready for use!")
print("Note: This is a minimal model trained on synthetic data.")
print("For production use, train with real binaries using train_advanced_model.py")