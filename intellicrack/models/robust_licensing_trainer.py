#!/usr/bin/env python3
"""
Robust Licensing Model Trainer

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

Trains a large, robust licensing detection model on hundreds of real binaries
with comprehensive feature extraction and ensemble methods.
"""

import os
import sys
import json
import joblib
import logging
import time
import shutil
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict, Counter
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.ensemble import ExtraTreesClassifier, AdaBoostClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Import our feature extractor with error handling
try:
    from .licensing_patterns_extractor import LicensingPatternsExtractor
except ImportError:
    try:
        from licensing_patterns_extractor import LicensingPatternsExtractor
    except ImportError:
        LicensingPatternsExtractor = None

logger = logging.getLogger(__name__)

class RobustLicensingTrainer:
    """Train robust licensing detection model on hundreds of samples"""
    
    def __init__(self, data_dir: str, output_dir: str):
        self.data_dir = Path(data_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.extractor = LicensingPatternsExtractor()
        self.feature_data = []
        self.labels = []
        self.category_mapping = {}
        self.file_paths = []
        
        # Categories that indicate licensing (label = 1)
        self.licensing_categories = {
            'commercial_adobe', 'commercial_git', 'commercial_java', 
            'commercial_maxon', 'commercial_microsoft', 'commercial_nodejs',
            'commercial_office', 'commercial_parsec', 'security_tools',
            'dev_tools'
        }
        
        # Categories that indicate no licensing (label = 0)  
        self.no_licensing_categories = {
            'no_licensing', 'system_linux'
        }
        
        # Mixed categories - analyze individually
        self.mixed_categories = {
            'system_windows'
        }
    
    def load_and_extract_features(self) -> Tuple[np.ndarray, np.ndarray]:
        """Load all binaries and extract comprehensive features"""
        logger.info("Loading and extracting features from collected binaries...")
        
        total_files = 0
        processed_files = 0
        
        # Count total files first
        for category_dir in self.data_dir.iterdir():
            if category_dir.is_dir():
                files = list(category_dir.glob('*'))
                total_files += len(files)
        
        logger.info(f"Found {total_files} total files to process")
        
        # Process each category
        for category_dir in self.data_dir.iterdir():
            if not category_dir.is_dir():
                continue
                
            category_name = category_dir.name
            files = list(category_dir.glob('*'))
            
            logger.info(f"Processing {len(files)} files from {category_name}")
            
            for file_path in files:
                try:
                    # Extract features
                    features = self.extractor.extract_features(str(file_path))
                    
                    if features:
                        # Convert to feature vector
                        feature_vector = self._dict_to_vector(features)
                        
                        # Determine label
                        label = self._determine_label(category_name, features, str(file_path))
                        
                        self.feature_data.append(feature_vector)
                        self.labels.append(label)
                        self.file_paths.append(str(file_path))
                        
                        processed_files += 1
                        
                        if processed_files % 50 == 0:
                            logger.info(f"Processed {processed_files}/{total_files} files ({processed_files/total_files*100:.1f}%)")
                
                except Exception as e:
                    logger.debug(f"Error processing {file_path}: {e}")
                    continue
        
        logger.info(f"Feature extraction complete: {processed_files} samples processed")
        
        # Convert to numpy arrays
        X = np.array(self.feature_data)
        y = np.array(self.labels)
        
        logger.info(f"Dataset shape: {X.shape}")
        logger.info(f"Label distribution: {Counter(y)}")
        
        return X, y
    
    def _dict_to_vector(self, features: Dict[str, float]) -> List[float]:
        """Convert feature dictionary to vector"""
        # Define feature order (must match extractor)
        feature_names = [
            'file_size', 'entropy', 'is_packed', 'is_pe', 'is_elf', 'has_digital_signature',
            'imports_registry_count', 'imports_crypto_count', 'imports_network_count',
            'imports_time_count', 'imports_hardware_count', 'imports_protection_count',
            'imports_file_count', 'has_resources', 'resource_count', 'section_count',
            'executable_sections', 'writable_sections', 'high_entropy_sections',
            'has_tls', 'is_dll', 'export_count', 'strings_license_files_count',
            'strings_license_keys_count', 'strings_license_text_count',
            'strings_registry_keys_count', 'strings_urls_count', 'strings_crypto_count',
            'has_license_key_pattern', 'license_url_count', 'has_support_email',
            'has_copyright', 'has_eula', 'function_count', 'licensing_functions',
            'crypto_functions', 'time_functions', 'code_string_refs',
            'anti_debug_instructions', 'has_indirect_calls', 'scheme_flexlm_score',
            'scheme_sentinel_score', 'scheme_codemeter_score', 'scheme_softwarepassport_score',
            'scheme_winlicense_score', 'scheme_asprotect_score', 'scheme_custom_score',
            'licensing_score', 'protection_level'
        ]
        
        return [features.get(name, 0.0) for name in feature_names]
    
    def _determine_label(self, category: str, features: Dict[str, float], file_path: str) -> int:
        """Determine binary label based on category and features"""
        if category in self.licensing_categories:
            return 1  # Has licensing
        elif category in self.no_licensing_categories:
            return 0  # No licensing
        elif category in self.mixed_categories:
            # Analyze features to determine
            licensing_score = features.get('licensing_score', 0.0)
            return 1 if licensing_score > 0.3 else 0
        else:
            # Default based on licensing indicators
            licensing_score = features.get('licensing_score', 0.0)
            return 1 if licensing_score > 0.5 else 0
    
    def train_robust_ensemble(self, X: np.ndarray, y: np.ndarray) -> Pipeline:
        """Train a robust ensemble model with multiple algorithms"""
        logger.info("Training robust ensemble model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        # Create individual models with optimized parameters
        rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=True,
            random_state=42,
            n_jobs=-1
        )
        
        gb_model = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=8,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        
        et_model = ExtraTreesClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            bootstrap=False,
            random_state=42,
            n_jobs=-1
        )
        
        ada_model = AdaBoostClassifier(
            n_estimators=100,
            learning_rate=1.0,
            random_state=42
        )
        
        # Create voting ensemble
        voting_classifier = VotingClassifier(
            estimators=[
                ('rf', rf_model),
                ('gb', gb_model), 
                ('et', et_model),
                ('ada', ada_model)
            ],
            voting='soft'
        )
        
        # Create pipeline with scaling
        pipeline = Pipeline([
            ('scaler', RobustScaler()),
            ('ensemble', voting_classifier)
        ])
        
        # Train the model
        logger.info("Training ensemble pipeline...")
        pipeline.fit(X_train, y_train)
        
        # Evaluate on test set
        y_pred = pipeline.predict(X_test)
        y_pred_proba = pipeline.predict_proba(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_pred_proba[:, 1])
        
        logger.info(f"Model Performance:")
        logger.info(f"  Accuracy: {accuracy:.4f}")
        logger.info(f"  Precision: {precision:.4f}")
        logger.info(f"  Recall: {recall:.4f}")
        logger.info(f"  F1-Score: {f1:.4f}")
        logger.info(f"  ROC-AUC: {roc_auc:.4f}")
        
        # Cross-validation
        cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring='f1')
        logger.info(f"Cross-validation F1: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        # Feature importance analysis
        self._analyze_feature_importance(pipeline, X_train, y_train)
        
        # Save performance metrics
        performance_metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'roc_auc': float(roc_auc),
            'cross_val_mean': float(cv_scores.mean()),
            'cross_val_std': float(cv_scores.std()),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True),
            'train_samples': int(X_train.shape[0]),
            'test_samples': int(X_test.shape[0]),
            'total_features': int(X.shape[1])
        }
        
        # Save metrics
        metrics_file = self.output_dir / 'robust_model_metrics.json'
        with open(metrics_file, 'w') as f:
            json.dump(performance_metrics, f, indent=2)
        
        logger.info(f"Performance metrics saved to {metrics_file}")
        
        return pipeline
    
    def _analyze_feature_importance(self, pipeline, X_train, y_train):
        """Analyze feature importance"""
        try:
            # Get the ensemble from pipeline
            ensemble = pipeline.named_steps['ensemble']
            
            # Get feature importances from Random Forest (first estimator)
            rf_estimator = ensemble.estimators_[0]  # Random Forest
            importances = rf_estimator.feature_importances_
            
            feature_names = [
                'file_size', 'entropy', 'is_packed', 'is_pe', 'is_elf', 'has_digital_signature',
                'imports_registry_count', 'imports_crypto_count', 'imports_network_count',
                'imports_time_count', 'imports_hardware_count', 'imports_protection_count',
                'imports_file_count', 'has_resources', 'resource_count', 'section_count',
                'executable_sections', 'writable_sections', 'high_entropy_sections',
                'has_tls', 'is_dll', 'export_count', 'strings_license_files_count',
                'strings_license_keys_count', 'strings_license_text_count',
                'strings_registry_keys_count', 'strings_urls_count', 'strings_crypto_count',
                'has_license_key_pattern', 'license_url_count', 'has_support_email',
                'has_copyright', 'has_eula', 'function_count', 'licensing_functions',
                'crypto_functions', 'time_functions', 'code_string_refs',
                'anti_debug_instructions', 'has_indirect_calls', 'scheme_flexlm_score',
                'scheme_sentinel_score', 'scheme_codemeter_score', 'scheme_softwarepassport_score',
                'scheme_winlicense_score', 'scheme_asprotect_score', 'scheme_custom_score',
                'licensing_score', 'protection_level'
            ]
            
            # Sort by importance
            importance_pairs = list(zip(feature_names, importances))
            importance_pairs.sort(key=lambda x: x[1], reverse=True)
            
            logger.info("Top 10 most important features:")
            for i, (feature, importance) in enumerate(importance_pairs[:10]):
                logger.info(f"  {i+1:2d}. {feature}: {importance:.4f}")
            
            # Save feature importances
            importance_data = {
                'feature_importances': {name: float(imp) for name, imp in importance_pairs},
                'top_features': importance_pairs[:20]
            }
            
            importance_file = self.output_dir / 'feature_importances.json'
            with open(importance_file, 'w') as f:
                json.dump(importance_data, f, indent=2)
        
        except Exception as e:
            logger.warning(f"Could not analyze feature importance: {e}")
    
    def save_robust_model(self, model: Pipeline) -> str:
        """Save the robust model with comprehensive metadata"""
        
        # Save the model
        model_file = self.output_dir / 'robust_licensing_model.joblib'
        joblib.dump(model, model_file)
        
        # Calculate model size
        model_size = os.path.getsize(model_file)
        logger.info(f"Robust model saved: {model_size:,} bytes ({model_size/1024/1024:.1f} MB)")
        
        # Create comprehensive metadata
        metadata = {
            'model_info': {
                'type': 'robust_licensing_ensemble',
                'description': 'Robust licensing detection model trained on hundreds of real binaries',
                'training_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                'version': '2.0_robust_real',
                'data_source': 'focused_real_licensing_binaries',
                'model_size_bytes': model_size,
                'model_size_mb': round(model_size / 1024 / 1024, 2)
            },
            'training_data': {
                'total_samples': len(self.feature_data),
                'licensing_samples': sum(self.labels),
                'no_licensing_samples': len(self.labels) - sum(self.labels),
                'feature_count': len(self.feature_data[0]) if self.feature_data else 0,
                'categories_processed': list(set(Path(fp).parent.name for fp in self.file_paths))
            },
            'model_architecture': {
                'pipeline_stages': ['RobustScaler', 'VotingClassifier'],
                'ensemble_methods': ['RandomForest', 'GradientBoosting', 'ExtraTrees', 'AdaBoost'],
                'voting_method': 'soft',
                'total_estimators': 650  # 200+150+200+100
            },
            'features': {
                'feature_names': [
                    'file_size', 'entropy', 'is_packed', 'is_pe', 'is_elf', 'has_digital_signature',
                    'imports_registry_count', 'imports_crypto_count', 'imports_network_count',
                    'imports_time_count', 'imports_hardware_count', 'imports_protection_count',
                    'imports_file_count', 'has_resources', 'resource_count', 'section_count',
                    'executable_sections', 'writable_sections', 'high_entropy_sections',
                    'has_tls', 'is_dll', 'export_count', 'strings_license_files_count',
                    'strings_license_keys_count', 'strings_license_text_count',
                    'strings_registry_keys_count', 'strings_urls_count', 'strings_crypto_count',
                    'has_license_key_pattern', 'license_url_count', 'has_support_email',
                    'has_copyright', 'has_eula', 'function_count', 'licensing_functions',
                    'crypto_functions', 'time_functions', 'code_string_refs',
                    'anti_debug_instructions', 'has_indirect_calls', 'scheme_flexlm_score',
                    'scheme_sentinel_score', 'scheme_codemeter_score', 'scheme_softwarepassport_score',
                    'scheme_winlicense_score', 'scheme_asprotect_score', 'scheme_custom_score',
                    'licensing_score', 'protection_level'
                ],
                'feature_count': 49
            }
        }
        
        # Save metadata
        metadata_file = self.output_dir / 'robust_licensing_model_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model metadata saved to {metadata_file}")
        
        return str(model_file)
    
    def deploy_robust_model(self, model_file: str):
        """Deploy robust model to all Intellicrack locations"""
        logger.info("Deploying robust model to Intellicrack locations...")
        
        # Deployment locations
        deployment_locations = [
            '/mnt/c/Intellicrack/intellicrack/models/vulnerability_model.joblib',
            '/mnt/c/Intellicrack/intellicrack/models/licensing_model.joblib',
            '/mnt/c/Intellicrack/intellicrack/ui/models/vuln_predict_model.joblib'
        ]
        
        metadata_locations = [
            '/mnt/c/Intellicrack/intellicrack/models/vulnerability_model_metadata.json',
            '/mnt/c/Intellicrack/intellicrack/models/licensing_model_metadata.json'
        ]
        
        # Copy model files
        for location in deployment_locations:
            try:
                os.makedirs(os.path.dirname(location), exist_ok=True)
                shutil.copy2(model_file, location)
                logger.info(f"Deployed robust model to {location}")
            except Exception as e:
                logger.error(f"Failed to deploy to {location}: {e}")
        
        # Copy metadata files
        source_metadata = self.output_dir / 'robust_licensing_model_metadata.json'
        for location in metadata_locations:
            try:
                shutil.copy2(source_metadata, location)
                logger.info(f"Deployed metadata to {location}")
            except Exception as e:
                logger.error(f"Failed to deploy metadata to {location}: {e}")
        
        logger.info("Robust model deployment complete!")


def main():
    """Main training function"""
    import argparse
    import time
    import shutil
    
    parser = argparse.ArgumentParser(description="Train robust licensing detection model")
    parser.add_argument("--data-dir", default="/mnt/c/Intellicrack/focused_licensing_data",
                       help="Directory containing collected licensing data")
    parser.add_argument("--output-dir", default="/mnt/c/Intellicrack/robust_model_output",
                       help="Output directory for trained model")
    
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(levelname)s - %(message)s')
    
    trainer = RobustLicensingTrainer(args.data_dir, args.output_dir)
    
    try:
        # Load and extract features
        X, y = trainer.load_and_extract_features()
        
        if len(X) == 0:
            logger.error("No features extracted! Check data directory.")
            return 1
        
        # Train robust ensemble model
        model = trainer.train_robust_ensemble(X, y)
        
        # Save model
        model_file = trainer.save_robust_model(model)
        
        # Deploy to Intellicrack
        trainer.deploy_robust_model(model_file)
        
        print("\n" + "="*80)
        print("ROBUST LICENSING MODEL TRAINING COMPLETE")
        print("="*80)
        print(f"Samples processed: {len(X)}")
        print(f"Features extracted: {X.shape[1]}")
        print(f"Model file: {model_file}")
        print(f"Model size: {os.path.getsize(model_file)/1024/1024:.1f} MB")
        print("="*80)
        
        return 0
    
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())