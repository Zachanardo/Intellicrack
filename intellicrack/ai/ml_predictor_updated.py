"""
Machine Learning Vulnerability Predictor - Updated to use Real ML Model

This module provides a wrapper around the real ML model implementation
to maintain compatibility with existing Intellicrack code while using
actual vulnerability detection instead of synthetic predictions.
"""

import os
import logging
from typing import Any, Dict, List, Optional, Tuple

# Import the new ML integration v2
try:
    from ..models.ml_integration_v2 import IntellicrackMLPredictor
    REAL_ML_AVAILABLE = True
except ImportError:
    REAL_ML_AVAILABLE = False

# Import legacy predictor as fallback
try:
    from .ml_predictor import MLVulnerabilityPredictor as LegacyPredictor
    LEGACY_AVAILABLE = True
except ImportError:
    LEGACY_AVAILABLE = False

from ..utils.logger import get_logger

logger = get_logger(__name__)


class MLVulnerabilityPredictor:
    """
    Updated ML Vulnerability Predictor that uses real trained models
    
    This class wraps the real ML integration to provide compatibility
    with existing Intellicrack code while delivering actual vulnerability
    detection capabilities.
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize predictor with real ML model
        
        Args:
            model_path: Optional path to a pre-trained model file
        """
        self.real_predictor = None
        self.legacy_predictor = None
        self.model_path = model_path
        self.logger = logger
        
        # Try to use real ML predictor first
        if REAL_ML_AVAILABLE:
            try:
                self.real_predictor = IntellicrackMLPredictor()
                if self.real_predictor.load_model():
                    self.logger.info("Real ML model loaded successfully")
                else:
                    self.logger.warning("Real ML model not found, will need training")
            except Exception as e:
                self.logger.error(f"Error initializing real ML predictor: {e}")
                self.real_predictor = None
        
        # Fallback to legacy predictor if needed
        if self.real_predictor is None and LEGACY_AVAILABLE:
            try:
                self.legacy_predictor = LegacyPredictor(model_path)
                self.logger.warning("Using legacy ML predictor as fallback")
            except Exception as e:
                self.logger.error(f"Error initializing legacy predictor: {e}")
    
    def predict_vulnerability(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Predict vulnerability likelihood for a binary file
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Dictionary with prediction results or None if prediction fails
        """
        # Try real predictor first
        if self.real_predictor:
            try:
                result = self.real_predictor.predict_vulnerability(binary_path)
                
                # Convert to expected format
                if result['success']:
                    return {
                        'prediction': 1 if result['prediction'] == 'vulnerable' else 0,
                        'probability': result['probability'],
                        'confidence': result['confidence'],
                        'vulnerability_type': result.get('vulnerability_type'),
                        'recommendations': result.get('recommendations', []),
                        'feature_importance': self._get_feature_importance(result),
                        'model_type': 'RealMLModel',
                        'feature_count': len(result.get('features', {}))
                    }
                else:
                    self.logger.error(f"Real ML prediction failed: {result.get('error')}")
            except Exception as e:
                self.logger.error(f"Error in real ML prediction: {e}")
        
        # Fallback to legacy predictor
        if self.legacy_predictor:
            try:
                return self.legacy_predictor.predict_vulnerability(binary_path)
            except Exception as e:
                self.logger.error(f"Legacy prediction also failed: {e}")
        
        # Return minimal result if all else fails
        return {
            'prediction': 0,
            'probability': 0.0,
            'confidence': 'low',
            'error': 'No ML model available',
            'model_type': 'None'
        }
    
    def predict_vulnerabilities(self, binary_path: str) -> Dict[str, Any]:
        """
        Predict vulnerabilities (compatibility method)
        
        Args:
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dictionary containing vulnerability predictions
        """
        result = self.predict_vulnerability(binary_path)
        
        if result:
            return {
                "status": "success",
                "binary_path": binary_path,
                "is_vulnerable": bool(result.get('prediction', 0)),
                "confidence": result.get('probability', 0.0),
                "vulnerability_type": result.get('vulnerability_type', 'unknown'),
                "recommendations": result.get('recommendations', []),
                "predictions": [
                    {
                        "type": result.get('vulnerability_type', 'vulnerability'),
                        "prediction": bool(result.get('prediction', 0)),
                        "confidence": result.get('probability', 0.0)
                    }
                ]
            }
        else:
            return {
                "status": "failed",
                "binary_path": binary_path,
                "error": "Prediction failed",
                "predictions": []
            }
    
    def batch_predict(self, binary_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Predict vulnerabilities for multiple binaries
        
        Args:
            binary_paths: List of binary file paths
            
        Returns:
            List of prediction results
        """
        if self.real_predictor and hasattr(self.real_predictor, 'batch_predict'):
            return self.real_predictor.batch_predict(binary_paths)  # pylint: disable=no-member
        
        # Fallback implementation
        results = []
        for path in binary_paths:
            result = self.predict_vulnerabilities(path)
            results.append(result)
        return results
    
    def train_model(self, training_data: List[Tuple[str, int]], 
                   model_output_path: Optional[str] = None) -> bool:
        """
        Train a new vulnerability prediction model
        
        Args:
            training_data: List of (binary_path, vulnerability_label) tuples
            model_output_path: Optional path to save the trained model
            
        Returns:
            bool: True if training successful
        """
        # Check if real ML training is available
        try:
            from ..models.train_real_model import train_model_from_real_data
            
            # Convert training data to dataset format
            self.logger.info("Training real ML model with provided data")
            
            # This would need to be implemented to convert the training data
            # For now, inform user to use the training script
            self.logger.warning("Direct training not implemented. Please use train_real_model.py")
            return False
            
        except ImportError:
            # Fallback to legacy training
            if self.legacy_predictor:
                return self.legacy_predictor.train_model(training_data, model_output_path)
            
            return False
    
    def load_model(self, model_path: str) -> bool:
        """
        Load a pre-trained model from file
        
        Args:
            model_path: Path to the model file
            
        Returns:
            bool: True if model loaded successfully
        """
        if self.real_predictor:
            # Real predictor loads from configured path
            return self.real_predictor.load_model()
        
        if self.legacy_predictor:
            return self.legacy_predictor.load_model(model_path)
        
        return False
    
    def save_model(self, model_path: str) -> bool:
        """
        Save the trained model to file
        
        Args:
            model_path: Path where to save the model
            
        Returns:
            bool: True if saved successfully
        """
        if self.real_predictor and hasattr(self.real_predictor, 'update_model'):
            return self.real_predictor.update_model(model_path)  # pylint: disable=no-member
        
        if self.legacy_predictor:
            return self.legacy_predictor.save_model(model_path)
        
        return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model
        
        Returns:
            Dictionary with model information
        """
        if self.real_predictor:
            return {
                'status': 'Real ML Model Loaded',
                'model_type': 'Ensemble (RandomForest + GradientBoosting)',
                'model_path': getattr(self.real_predictor, 'model_path', 'Unknown'),
                'metadata': getattr(self.real_predictor, 'model_metadata', {}),
                'feature_extractor': 'RealFeatureExtractor'
            }
        
        if self.legacy_predictor:
            return self.legacy_predictor.get_model_info()
        
        return {'status': 'No model loaded'}
    
    def _get_feature_importance(self, result: Dict[str, Any]) -> Optional[List[float]]:
        """
        Extract feature importance from result
        
        Args:
            result: Prediction result dictionary
            
        Returns:
            List of feature importances or None
        """
        # Could be enhanced to return actual feature importances
        # from the real model if available
        features = result.get('features', {})
        if features:
            # Return normalized feature values as proxy for importance
            values = list(features.values())
            max_val = max(values) if values else 1.0
            return [v / max_val for v in values]
        return None
    
    def get_confidence_score(self, binary_path: str) -> float:
        """
        Get confidence score for a prediction
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Confidence score between 0 and 1
        """
        result = self.predict_vulnerability(binary_path)
        if result:
            return result.get('probability', 0.0)
        return 0.0
    
    def analyze_binary_features(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary features for ML prediction
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Dictionary containing feature analysis
        """
        if self.real_predictor:
            result = self.real_predictor.predict_vulnerability(binary_path)
            if result['success']:
                return {
                    'features': result.get('features', {}),
                    'feature_count': len(result.get('features', {})),
                    'vulnerability_indicators': self._analyze_vulnerability_indicators(result),
                    'recommendations': result.get('recommendations', [])
                }
        
        if self.legacy_predictor:
            return self.legacy_predictor.analyze_binary_features(binary_path)
        
        return {'error': 'No model available for analysis'}
    
    def _analyze_vulnerability_indicators(self, result: Dict[str, Any]) -> List[str]:
        """
        Analyze vulnerability indicators from features
        
        Args:
            result: Prediction result with features
            
        Returns:
            List of vulnerability indicators found
        """
        indicators = []
        features = result.get('features', {})
        
        # Check for high-risk features
        if features.get('pe_has_nx', 1) == 0:
            indicators.append('Missing DEP/NX protection')
        
        if features.get('pe_has_aslr', 1) == 0:
            indicators.append('Missing ASLR protection')
        
        if features.get('pe_is_signed', 1) == 0:
            indicators.append('Binary is not digitally signed')
        
        if features.get('entropy_overall', 0) > 7.0:
            indicators.append('High entropy suggests packing/encryption')
        
        if features.get('strings_license_count', 0) > 5:
            indicators.append('Multiple licensing-related strings detected')
        
        if features.get('imports_crypto_count', 0) > 5:
            indicators.append('Heavy use of cryptographic functions')
        
        if features.get('packer_generic', 0) == 1:
            indicators.append('Packer/protector detected')
        
        return indicators


# Convenience functions for compatibility

def predict_vulnerabilities(binary_path: str, model_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Standalone function to predict vulnerabilities in a binary
    
    Args:
        binary_path: Path to the binary file to analyze
        model_path: Optional path to custom model
        
    Returns:
        Dictionary containing vulnerability predictions
    """
    predictor = MLVulnerabilityPredictor(model_path)
    return predictor.predict_vulnerabilities(binary_path)


def get_ml_predictor(model_path: Optional[str] = None) -> MLVulnerabilityPredictor:
    """
    Get an instance of the ML predictor
    
    Args:
        model_path: Optional path to custom model
        
    Returns:
        MLVulnerabilityPredictor instance
    """
    return MLVulnerabilityPredictor(model_path)


# Aliases for compatibility
MLPredictor = MLVulnerabilityPredictor
VulnerabilityPredictor = MLVulnerabilityPredictor

__all__ = [
    'MLVulnerabilityPredictor',
    'MLPredictor', 
    'VulnerabilityPredictor',
    'predict_vulnerabilities',
    'get_ml_predictor'
]