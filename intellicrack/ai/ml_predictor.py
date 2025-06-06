"""
Machine Learning Vulnerability Predictor

This module provides machine learning capabilities for vulnerability prediction
and binary analysis using trained models for security research.
"""

import os
import pickle
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Third-party imports with graceful fallbacks
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import importlib.util
    PEFILE_AVAILABLE = importlib.util.find_spec("pefile") is not None
except ImportError:
    PEFILE_AVAILABLE = False

# Local imports
from ..core.analysis.vulnerability_engine import calculate_entropy
from ..utils.logger import get_logger

# Configure module logger
logger = get_logger(__name__)


class MLVulnerabilityPredictor:
    """
    Machine Learning-powered Vulnerability Prediction

    This class provides ML-based vulnerability detection and prediction
    capabilities for binary analysis and security research.
    """

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize predictor with optional pre-trained model.

        Args:
            model_path: Optional path to a pre-trained model file
        """
        self.model = None
        self.scaler = None
        self.model_path = None
        self.logger = logger
        self.feature_names = []

        self.logger.info("MLVulnerabilityPredictor initializing with model_path: %s", model_path)

        # Check dependencies
        if not SKLEARN_AVAILABLE:
            self.logger.warning("scikit-learn not available, ML prediction disabled")
            return

        if not JOBLIB_AVAILABLE:
            self.logger.warning("joblib not available, model loading may be limited")

        # Try to load default model from config if no path provided
        if not model_path:
            try:
                from ..config import CONFIG
                model_path = CONFIG.get("ml", {}).get("vulnerability_model_path")
                if model_path and os.path.exists(model_path):
                    self.logger.info("Using default ML model from config: %s", model_path)
                else:
                    self.logger.warning("Default ML model not found at: %s", model_path)
            except Exception as e:
                self.logger.error("Error loading config for ML model: %s", e)

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
            if self.model is not None:
                self.model_path = model_path
        else:
            self.logger.warning("No valid ML model path provided or model file not found")

        self.logger.info("MLVulnerabilityPredictor initialization complete.")

    def load_model(self, model_path: str) -> bool:
        """
        Load a pre-trained model from file.

        Args:
            model_path: Path to the model file

        Returns:
            bool: True if model loaded successfully, False otherwise
        """
        try:
            self.logger.info("Loading ML model from: %s", model_path)

            if JOBLIB_AVAILABLE:
                # Try joblib first (preferred for sklearn models)
                try:
                    model_data = joblib.load(model_path)

                    if isinstance(model_data, dict):
                        self.model = model_data.get('model')
                        self.scaler = model_data.get('scaler')
                        self.feature_names = model_data.get('feature_names', [])
                    else:
                        # Assume it's just the model
                        self.model = model_data
                        self.scaler = StandardScaler()  # Create default scaler

                except Exception as e:
                    self.logger.warning("joblib loading failed: %s, trying pickle", e)
                    raise e

            # Fallback to pickle if joblib fails or isn't available
            if self.model is None:
                with open(model_path, 'rb') as f:
                    model_data = pickle.load(f)

                    if isinstance(model_data, dict):
                        self.model = model_data.get('model')
                        self.scaler = model_data.get('scaler')
                        self.feature_names = model_data.get('feature_names', [])
                    else:
                        self.model = model_data
                        self.scaler = StandardScaler()

            if self.model is not None:
                self.logger.info(f"Successfully loaded model: {type(self.model).__name__}")
                return True
            else:
                self.logger.error("Failed to load model: model is None")
                return False

        except Exception as e:
            self.logger.error("Error loading model from %s: %s", model_path, e)
            return False

    def extract_features(self, binary_path: str) -> Optional[np.ndarray]:
        """
        Extract features from a binary file for ML prediction.

        Args:
            binary_path: Path to the binary file

        Returns:
            numpy.ndarray or None: Feature vector for prediction
        """
        if not SKLEARN_AVAILABLE:
            self.logger.error("scikit-learn not available, cannot extract features")
            return None

        try:
            self.logger.debug("Extracting features from: %s", binary_path)
            features = []

            # Read binary data
            with open(binary_path, 'rb') as f:
                binary_data = f.read()

            # Basic file size feature
            features.append(len(binary_data))

            # Entropy calculation
            entropy = calculate_entropy(binary_data)
            features.append(entropy)

            # Byte frequency analysis (simplified)
            byte_counts = np.zeros(256)
            for byte in binary_data[:10000]:  # Sample first 10KB for performance
                byte_counts[byte] += 1

            # Normalize byte frequencies
            if len(binary_data) > 0:
                byte_frequencies = byte_counts / min(len(binary_data), 10000)
            else:
                byte_frequencies = byte_counts

            features.extend(byte_frequencies.tolist())

            # PE file analysis if available
            if PEFILE_AVAILABLE:
                try:
                    pe_features = self._extract_pe_features(binary_path)
                    features.extend(pe_features)
                except Exception as e:
                    self.logger.warning("PE feature extraction failed: %s", e)
                    # Add default PE features that match expected structure
                    features.extend([
                        4,      # NumberOfSections (typical)
                        0,      # TimeDateStamp
                        4096,   # SizeOfCode (typical small binary)
                        2048,   # SizeOfInitializedData
                        4096,   # AddressOfEntryPoint
                        1, 0, 1024,  # Section 1: executable, not writable, 1KB
                        0, 1, 512,   # Section 2: not executable, writable, 512B
                        0, 0, 256,   # Section 3: neither, 256B
                        10,     # Import count
                        2,      # Dangerous import count
                        1,      # Has resources
                        0,      # Is signed
                        0       # Is packed
                    ])
            else:
                # Add default PE features if pefile not available
                features.extend([
                    4,      # NumberOfSections (typical)
                    0,      # TimeDateStamp
                    4096,   # SizeOfCode (typical small binary)
                    2048,   # SizeOfInitializedData
                    4096,   # AddressOfEntryPoint
                    1, 0, 1024,  # Section 1: executable, not writable, 1KB
                    0, 1, 512,   # Section 2: not executable, writable, 512B
                    0, 0, 256,   # Section 3: neither, 256B
                    10,     # Import count
                    2,      # Dangerous import count
                    1,      # Has resources
                    0,      # Is signed
                    0       # Is packed
                ])

            self.logger.debug(f"Extracted {len(features)} features")
            return np.array(features).reshape(1, -1)

        except Exception as e:
            self.logger.error("Feature extraction error: %s", e)
            return None

    def _extract_pe_features(self, binary_path: str) -> List[float]:
        """
        Extract PE-specific features.

        Args:
            binary_path: Path to the PE file

        Returns:
            List of PE-specific features
        """
        import pefile

        features = []

        try:
            pe = pefile.PE(binary_path)

            # Basic PE header features
            features.append(getattr(pe.FILE_HEADER, 'NumberOfSections', 0))
            features.append(getattr(pe.FILE_HEADER, 'TimeDateStamp', 0))
            features.append(getattr(pe.OPTIONAL_HEADER, 'SizeOfCode', 0))
            features.append(getattr(pe.OPTIONAL_HEADER, 'SizeOfInitializedData', 0))
            features.append(getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0))

            # Section characteristics (process up to 3 sections)
            for i, section in enumerate(pe.sections[:3]):
                features.append(int(section.Characteristics & 0x20000000 > 0))  # Executable
                features.append(int(section.Characteristics & 0x80000000 > 0))  # Writable
                features.append(len(section.get_data()))

            # Pad if fewer than 3 sections
            while len(features) < 5 + (3 * 3):  # 5 header + 3*3 section features
                features.append(0)

            # Import analysis
            import_count = 0
            dangerous_import_count = 0
            dangerous_keywords = ['exec', 'shell', 'process', 'alloc', 'protect']

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        import_count += 1
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore').lower()
                            if any(keyword in func_name for keyword in dangerous_keywords):
                                dangerous_import_count += 1

            features.append(import_count)
            features.append(dangerous_import_count)

        except Exception as e:
            self.logger.warning("PE feature extraction error: %s", e)
            # Return zeros if PE analysis fails
            features = [0] * 20

        # Ensure we return exactly 20 features
        features = features[:20]
        while len(features) < 20:
            features.append(0)

        return features

    def predict_vulnerability(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """
        Predict vulnerability likelihood for a binary file.

        Args:
            binary_path: Path to the binary file

        Returns:
            Dictionary with prediction results or None if prediction fails
        """
        if self.model is None:
            self.logger.error("No model loaded, cannot make predictions")
            return None

        try:
            # Extract features
            features = self.extract_features(binary_path)
            if features is None:
                return None

            # Scale features if scaler is available
            if self.scaler is not None:
                try:
                    features = self.scaler.transform(features)
                except Exception as e:
                    self.logger.warning("Feature scaling failed: %s, using raw features", e)

            # Make prediction
            prediction = self.model.predict(features)[0]

            # Get prediction probability if available
            probability = None
            if hasattr(self.model, 'predict_proba'):
                try:
                    probabilities = self.model.predict_proba(features)[0]
                    probability = float(max(probabilities))
                except Exception as e:
                    self.logger.warning("Probability calculation failed: %s", e)

            # Get feature importance if available
            feature_importance = None
            if hasattr(self.model, 'feature_importances_'):
                try:
                    feature_importance = self.model.feature_importances_.tolist()
                except Exception as e:
                    self.logger.warning("Feature importance extraction failed: %s", e)

            result = {
                'prediction': int(prediction),
                'probability': probability,
                'feature_importance': feature_importance,
                'model_type': type(self.model).__name__,
                'feature_count': features.shape[1]
            }

            self.logger.info("Vulnerability prediction: %s (probability: %s)", prediction, probability)
            return result

        except Exception as e:
            self.logger.error("Prediction error: %s", e)
            return None

    def train_model(self, training_data: List[Tuple[str, int]],
                   model_output_path: Optional[str] = None) -> bool:
        """
        Train a new vulnerability prediction model.

        Args:
            training_data: List of (binary_path, vulnerability_label) tuples
            model_output_path: Optional path to save the trained model

        Returns:
            bool: True if training successful, False otherwise
        """
        if not SKLEARN_AVAILABLE:
            self.logger.error("scikit-learn not available, cannot train model")
            return False

        try:
            self.logger.info(f"Training model with {len(training_data)} samples")

            # Extract features for all training samples
            X = []
            y = []

            for binary_path, label in training_data:
                features = self.extract_features(binary_path)
                if features is not None:
                    X.append(features[0])  # Remove the extra dimension
                    y.append(label)

            if len(X) == 0:
                self.logger.error("No valid training samples found")
                return False

            X = np.array(X)
            y = np.array(y)

            self.logger.info(f"Training with {X.shape[0]} samples, {X.shape[1]} features")

            # Initialize and fit scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10,
                min_samples_split=5
            )
            self.model.fit(X_scaled, y)

            self.logger.info("Model training completed successfully")

            # Save model if path provided
            if model_output_path:
                self.save_model(model_output_path)

            return True

        except Exception as e:
            self.logger.error("Model training error: %s", e)
            return False

    def save_model(self, model_path: str) -> bool:
        """
        Save the trained model to file.

        Args:
            model_path: Path where to save the model

        Returns:
            bool: True if saved successfully, False otherwise
        """
        if self.model is None:
            self.logger.error("No model to save")
            return False

        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names
            }

            if JOBLIB_AVAILABLE:
                joblib.dump(model_data, model_path)
            else:
                with open(model_path, 'wb') as f:
                    pickle.dump(model_data, f)

            self.logger.info("Model saved to: %s", model_path)
            return True

        except Exception as e:
            self.logger.error("Error saving model to %s: %s", model_path, e)
            return False

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model.

        Returns:
            Dictionary with model information
        """
        if self.model is None:
            return {'status': 'No model loaded'}

        info = {
            'status': 'Model loaded',
            'model_type': type(self.model).__name__,
            'model_path': self.model_path,
            'has_scaler': self.scaler is not None,
            'feature_count': len(self.feature_names) if self.feature_names else 'Unknown'
        }

        # Add model-specific information
        if hasattr(self.model, 'n_estimators'):
            info['n_estimators'] = self.model.n_estimators
        if hasattr(self.model, 'max_depth'):
            info['max_depth'] = self.model.max_depth

        return info

    def predict_vulnerabilities(self, binary_path: str) -> Dict[str, Any]:
        """
        Predict vulnerabilities in a binary file.
        
        Args:
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dictionary containing vulnerability predictions
        """
        try:
            if self.model is None:
                return {
                    "error": "No model loaded",
                    "status": "failed",
                    "predictions": []
                }

            # Extract features from binary
            features = self.extract_features(binary_path)
            if features is None:
                return {
                    "error": "Failed to extract features",
                    "status": "failed", 
                    "predictions": []
                }

            # Scale features if scaler is available
            if self.scaler is not None:
                features = self.scaler.transform(features.reshape(1, -1))
            else:
                features = features.reshape(1, -1)

            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Get prediction probability if available
            prediction_proba = None
            if hasattr(self.model, 'predict_proba'):
                prediction_proba = self.model.predict_proba(features)[0]

            # Format results
            result = {
                "status": "success",
                "binary_path": binary_path,
                "is_vulnerable": bool(prediction),
                "confidence": float(prediction_proba[1]) if prediction_proba is not None else None,
                "predictions": [
                    {
                        "type": "vulnerability",
                        "prediction": bool(prediction),
                        "confidence": float(prediction_proba[1]) if prediction_proba is not None else None
                    }
                ]
            }

            return result

        except Exception as e:
            self.logger.error("Error predicting vulnerabilities: %s", e)
            return {
                "error": str(e),
                "status": "failed",
                "predictions": []
            }

    def _extract_features(self, binary_path: str) -> Optional[np.ndarray]:
        """
        Extract features for ML prediction (alias for extract_features).
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Feature array or None if extraction failed
        """
        return self.extract_features(binary_path)

    def predict(self, binary_path: str) -> Dict[str, Any]:
        """
        Predict method for compatibility (alias for predict_vulnerabilities).
        
        Args:
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dictionary containing vulnerability predictions
        """
        return self.predict_vulnerabilities(binary_path)

    def get_confidence_score(self, binary_path: str) -> float:
        """
        Get confidence score for a prediction.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Confidence score between 0 and 1
        """
        try:
            result = self.predict_vulnerabilities(binary_path)
            return result.get('confidence', 0.0) or 0.0
        except Exception as e:
            self.logger.error("Error getting confidence score: %s", e)
            return 0.0

    def analyze_binary_features(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary features for ML prediction.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Dictionary containing feature analysis
        """
        try:
            features = self.extract_features(binary_path)
            if features is None:
                return {"error": "Failed to extract features"}
                
            analysis = {
                "feature_count": len(features),
                "features": features.tolist() if hasattr(features, 'tolist') else features,
                "feature_names": self.feature_names if self.feature_names else None
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error("Error analyzing binary features: %s", e)
            return {"error": str(e)}


# Standalone convenience functions for backward compatibility

# Create aliases for common use
MLPredictor = MLVulnerabilityPredictor
VulnerabilityPredictor = MLVulnerabilityPredictor


def predict_vulnerabilities(binary_path: str, model_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Standalone function to predict vulnerabilities in a binary.
    
    Args:
        binary_path: Path to the binary file to analyze
        model_path: Optional path to custom model
        
    Returns:
        Dictionary containing vulnerability predictions
    """
    try:
        predictor = MLVulnerabilityPredictor(model_path)
        return predictor.predict_vulnerabilities(binary_path)
    except Exception as e:
        logger.error("Vulnerability prediction failed: %s", e)
        return {
            "error": str(e),
            "status": "failed",
            "predictions": []
        }


def train_model(training_data: List[Tuple[str, int]], 
               model_output_path: str,
               model_type: str = "random_forest") -> Dict[str, Any]:
    """
    Train a new vulnerability prediction model.
    
    Args:
        training_data: List of (binary_path, is_vulnerable) tuples
        model_output_path: Where to save the trained model
        model_type: Type of model to train
        
    Returns:
        Training results and metrics
    """
    try:
        predictor = MLVulnerabilityPredictor()
        
        # Extract features and labels
        X_data = []
        y_data = []
        
        for binary_path, label in training_data:
            try:
                features = predictor._extract_features(binary_path)
                X_data.append(features)
                y_data.append(label)
            except Exception as e:
                logger.warning("Failed to extract features from %s: %s", binary_path, e)
                continue
        
        if not X_data:
            return {
                "error": "No valid training data extracted",
                "status": "failed"
            }
        
        X = np.array(X_data)
        y = np.array(y_data)
        
        # Train model based on type
        if model_type == "random_forest" and SKLEARN_AVAILABLE:
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, classification_report
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Train model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Save model
            if JOBLIB_AVAILABLE:
                joblib.dump(model, model_output_path)
            else:
                with open(model_output_path, 'wb') as f:
                    pickle.dump(model, f)
            
            return {
                "status": "success",
                "model_type": model_type,
                "model_path": model_output_path,
                "accuracy": accuracy,
                "training_samples": len(X_train),
                "test_samples": len(X_test)
            }
        else:
            return {
                "error": f"Model type '{model_type}' not supported or dependencies missing",
                "status": "failed"
            }
            
    except Exception as e:
        logger.error("Model training failed: %s", e)
        return {
            "error": str(e),
            "status": "failed"
        }


def evaluate_model(model_path: str, test_data: List[Tuple[str, int]]) -> Dict[str, Any]:
    """
    Evaluate a trained model on test data.
    
    Args:
        model_path: Path to the trained model
        test_data: List of (binary_path, expected_label) tuples
        
    Returns:
        Evaluation metrics and results
    """
    try:
        predictor = MLVulnerabilityPredictor(model_path)
        
        predictions = []
        actual_labels = []
        
        for binary_path, expected_label in test_data:
            try:
                result = predictor.predict_vulnerabilities(binary_path)
                
                # Extract prediction (assuming highest confidence prediction)
                if result.get("predictions"):
                    prediction = max(result["predictions"], key=lambda x: x.get("confidence", 0))
                    predicted_label = 1 if prediction.get("confidence", 0) > 0.5 else 0
                else:
                    predicted_label = 0
                
                predictions.append(predicted_label)
                actual_labels.append(expected_label)
                
            except Exception as e:
                logger.warning("Failed to predict for %s: %s", binary_path, e)
                continue
        
        if not predictions:
            return {
                "error": "No valid predictions generated",
                "status": "failed"
            }
        
        # Calculate metrics
        correct = sum(1 for p, a in zip(predictions, actual_labels) if p == a)
        accuracy = correct / len(predictions)
        
        # Calculate precision, recall for positive class
        tp = sum(1 for p, a in zip(predictions, actual_labels) if p == 1 and a == 1)
        fp = sum(1 for p, a in zip(predictions, actual_labels) if p == 1 and a == 0)
        fn = sum(1 for p, a in zip(predictions, actual_labels) if p == 0 and a == 1)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            "status": "success",
            "model_path": model_path,
            "test_samples": len(predictions),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn
        }
        
    except Exception as e:
        logger.error("Model evaluation failed: %s", e)
        return {
            "error": str(e),
            "status": "failed"
        }


# Export all classes and functions
__all__ = [
    'MLVulnerabilityPredictor', 
    'MLPredictor', 
    'VulnerabilityPredictor',
    'predict_vulnerabilities',
    'train_model', 
    'evaluate_model'
]
