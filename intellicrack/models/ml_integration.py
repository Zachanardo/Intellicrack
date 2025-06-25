#!/usr/bin/env python3
"""
ML Model Integration for Intellicrack

This module integrates the real ML model into Intellicrack's existing
infrastructure, replacing synthetic predictions with actual vulnerability analysis.
"""

import os
import json
import logging
import joblib
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)


class IntellicrackMLPredictor:
    """
    ML Predictor that uses real trained models for vulnerability detection
    """
    
    def __init__(self):
        self.model = None
        self.feature_extractor = None
        self.model_metadata = {}
        self.model_path = os.path.join(os.path.dirname(__file__), "vulnerability_model.joblib")
        self.metadata_path = os.path.join(os.path.dirname(__file__), "vulnerability_model_metadata.json")
        
    def load_model(self) -> bool:
        """
        Load the trained ML model and metadata
        
        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        try:
            # Check if model exists
            if not os.path.exists(self.model_path):
                logger.warning(f"Model not found at {self.model_path}")
                logger.info("Please run train_real_model.py to train the model first")
                return False
            
            # Load model
            logger.info(f"Loading ML model from {self.model_path}")
            self.model = joblib.load(self.model_path)
            
            # Load metadata
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path, 'r') as f:
                    self.model_metadata = json.load(f)
                logger.info(f"Model version: {self.model_metadata.get('version', 'unknown')}")
                logger.info(f"Trained on: {self.model_metadata.get('trained_at', 'unknown')}")
                logger.info(f"Accuracy: {self.model_metadata.get('accuracy', 0):.4f}")
                logger.info(f"ROC AUC: {self.model_metadata.get('roc_auc', 0):.4f}")
            
            # Load feature extractor
            try:
                from real_feature_extractor import RealFeatureExtractor
                self.feature_extractor = RealFeatureExtractor()
                logger.info("Feature extractor loaded successfully")
            except ImportError:
                logger.error("Could not import RealFeatureExtractor")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def predict_vulnerability(self, binary_path: str) -> Dict[str, any]:
        """
        Predict vulnerability likelihood for a binary
        
        Args:
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dict containing prediction results
        """
        result = {
            'success': False,
            'binary_path': binary_path,
            'prediction': None,
            'probability': 0.0,
            'vulnerability_type': None,
            'confidence': 'low',
            'features': {},
            'recommendations': [],
            'error': None
        }
        
        try:
            # Ensure model is loaded
            if self.model is None:
                if not self.load_model():
                    result['error'] = "Model not loaded"
                    return result
            
            # Check if file exists
            if not os.path.exists(binary_path):
                result['error'] = f"File not found: {binary_path}"
                return result
            
            # Extract features
            logger.info(f"Extracting features from {binary_path}")
            features = self.feature_extractor.extract_features(binary_path)
            
            # Convert to feature vector
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Make prediction
            prediction = self.model.predict(feature_vector)[0]
            probabilities = self.model.predict_proba(feature_vector)[0]
            
            # Get vulnerability probability
            vuln_probability = probabilities[1] if len(probabilities) > 1 else 0.0
            
            # Determine confidence level
            if vuln_probability > 0.8:
                confidence = 'high'
            elif vuln_probability > 0.6:
                confidence = 'medium'
            else:
                confidence = 'low'
            
            # Update result
            result['success'] = True
            result['prediction'] = 'vulnerable' if prediction == 1 else 'secure'
            result['probability'] = float(vuln_probability)
            result['confidence'] = confidence
            result['features'] = self._get_top_features(features, feature_vector)
            
            # Determine vulnerability type based on features
            result['vulnerability_type'] = self._determine_vulnerability_type(features)
            
            # Generate recommendations
            result['recommendations'] = self._generate_recommendations(features, vuln_probability)
            
            logger.info(f"Prediction complete: {result['prediction']} "
                       f"(probability: {result['probability']:.4f})")
            
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            result['error'] = str(e)
        
        return result
    
    def _get_top_features(self, features: Dict[str, float], 
                         feature_vector: np.ndarray) -> Dict[str, float]:
        """
        Get top contributing features for the prediction
        
        Args:
            features: Raw feature dictionary
            feature_vector: Processed feature vector
            
        Returns:
            Dict of top features and their values
        """
        top_features = {}
        
        try:
            # If model has feature importances (e.g., RandomForest)
            if hasattr(self.model, 'named_steps') and 'model' in self.model.named_steps:
                ensemble = self.model.named_steps['model']
                if hasattr(ensemble, 'estimators_'):
                    rf = ensemble.estimators_[0]  # Get RandomForest
                    if hasattr(rf, 'feature_importances_'):
                        importances = rf.feature_importances_
                        
                        # Get preprocessed values
                        preprocessed = self.model.named_steps['preprocessing'].transform(feature_vector)[0]
                        
                        # Calculate contributions
                        contributions = importances * np.abs(preprocessed)
                        top_indices = np.argsort(contributions)[-10:][::-1]
                        
                        feature_keys = list(features.keys())
                        for idx in top_indices:
                            if idx < len(feature_keys):
                                key = feature_keys[idx]
                                top_features[key] = features[key]
        except:
            # Fallback: return features with high values
            sorted_features = sorted(features.items(), 
                                   key=lambda x: abs(x[1]), 
                                   reverse=True)[:10]
            top_features = dict(sorted_features)
        
        return top_features
    
    def _determine_vulnerability_type(self, features: Dict[str, float]) -> str:
        """
        Determine the most likely vulnerability type based on features
        
        Args:
            features: Feature dictionary
            
        Returns:
            str: Vulnerability type
        """
        # Check for licensing-specific indicators
        if features.get('strings_license_count', 0) > 5:
            if features.get('strings_serial_count', 0) > 3:
                return 'licensing_weakness'
            elif features.get('strings_trial_count', 0) > 3:
                return 'trial_bypass'
        
        # Check for crypto weaknesses
        if features.get('imports_crypto_count', 0) > 5:
            if features.get('entropy_overall', 0) < 6:
                return 'weak_cryptography'
        
        # Check for network vulnerabilities
        if features.get('imports_network_count', 0) > 10:
            return 'network_vulnerability'
        
        # Check for memory vulnerabilities
        if features.get('pe_has_nx', 0) == 0 or features.get('pe_has_aslr', 0) == 0:
            return 'memory_vulnerability'
        
        # Check for time-based vulnerabilities
        if features.get('imports_time_count', 0) > 3 and features.get('strings_time_refs', 0) > 2:
            return 'time_based_protection'
        
        # Default
        return 'general_vulnerability'
    
    def _generate_recommendations(self, features: Dict[str, float], 
                                 probability: float) -> List[str]:
        """
        Generate security recommendations based on analysis
        
        Args:
            features: Feature dictionary
            probability: Vulnerability probability
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if probability > 0.7:
            recommendations.append("HIGH RISK: This binary shows strong indicators of vulnerabilities")
        
        # Check specific weaknesses
        if features.get('pe_has_nx', 0) == 0:
            recommendations.append("Enable DEP/NX bit for memory protection")
        
        if features.get('pe_has_aslr', 0) == 0:
            recommendations.append("Enable ASLR for address space randomization")
        
        if features.get('pe_is_signed', 0) == 0:
            recommendations.append("Binary is not digitally signed - verify authenticity")
        
        if features.get('strings_license_count', 0) > 5:
            recommendations.append("Licensing mechanism detected - review for bypass vulnerabilities")
        
        if features.get('imports_crypto_count', 0) > 0 and features.get('entropy_overall', 0) < 6:
            recommendations.append("Weak cryptography detected - review encryption implementation")
        
        if features.get('packer_generic', 0) == 1:
            recommendations.append("Binary appears to be packed - unpack for deeper analysis")
        
        if features.get('imports_debug_count', 0) > 0:
            recommendations.append("Anti-debugging functions detected - may hinder analysis")
        
        if features.get('strings_trial_count', 0) > 3:
            recommendations.append("Trial/evaluation logic detected - check for time-based bypasses")
        
        return recommendations
    
    def batch_predict(self, binary_paths: List[str]) -> List[Dict[str, any]]:
        """
        Predict vulnerabilities for multiple binaries
        
        Args:
            binary_paths: List of binary file paths
            
        Returns:
            List of prediction results
        """
        results = []
        
        for path in binary_paths:
            logger.info(f"Analyzing {path}")
            result = self.predict_vulnerability(path)
            results.append(result)
        
        return results
    
    def update_model(self, new_model_path: str) -> bool:
        """
        Update the model with a new version
        
        Args:
            new_model_path: Path to new model file
            
        Returns:
            bool: True if update successful
        """
        try:
            # Backup current model
            if os.path.exists(self.model_path):
                backup_path = self.model_path + f".backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                os.rename(self.model_path, backup_path)
                logger.info(f"Backed up current model to {backup_path}")
            
            # Copy new model
            import shutil
            shutil.copy2(new_model_path, self.model_path)
            
            # Reload model
            return self.load_model()
            
        except Exception as e:
            logger.error(f"Error updating model: {e}")
            return False


# Integration with existing Intellicrack code
def integrate_ml_predictions(binary_path: str) -> Dict[str, any]:
    """
    Main integration function to be called from Intellicrack
    
    Args:
        binary_path: Path to binary to analyze
        
    Returns:
        Dict with vulnerability analysis results
    """
    predictor = IntellicrackMLPredictor()
    return predictor.predict_vulnerability(binary_path)


if __name__ == "__main__":
    # Test the integration
    import sys
    
    if len(sys.argv) > 1:
        test_binary = sys.argv[1]
        
        # Create predictor
        predictor = IntellicrackMLPredictor()
        
        # Make prediction
        result = predictor.predict_vulnerability(test_binary)
        
        # Display results
        print("\n" + "="*60)
        print("INTELLICRACK ML VULNERABILITY ANALYSIS")
        print("="*60)
        print(f"Binary: {result['binary_path']}")
        print(f"Prediction: {result['prediction'].upper()}")
        print(f"Probability: {result['probability']:.2%}")
        print(f"Confidence: {result['confidence'].upper()}")
        print(f"Type: {result['vulnerability_type']}")
        
        if result['recommendations']:
            print("\nRecommendations:")
            for i, rec in enumerate(result['recommendations'], 1):
                print(f"{i}. {rec}")
        
        if result['error']:
            print(f"\nError: {result['error']}")
        
        print("="*60)
    else:
        print("Usage: python ml_integration.py <binary_path>")