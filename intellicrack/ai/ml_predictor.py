"""
Machine Learning Vulnerability Predictor

This module provides machine learning capabilities for vulnerability prediction
and binary analysis using trained models for security research.
"""

import logging
import os
import pickle
from typing import List, Dict, Any, Optional, Tuple
import numpy as np

# Third-party imports with graceful fallbacks
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import sklearn
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

# Local imports
from ..utils.logger import get_logger
from ..core.analysis.vulnerability_engine import calculate_entropy

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
        
        self.logger.info(f"MLVulnerabilityPredictor initializing with model_path: {model_path}")

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
                    self.logger.info(f"Using default ML model from config: {model_path}")
                else:
                    self.logger.warning(f"Default ML model not found at: {model_path}")
            except Exception as e:
                self.logger.error(f"Error loading config for ML model: {e}")

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
            self.logger.info(f"Loading ML model from: {model_path}")
            
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
                    self.logger.warning(f"joblib loading failed: {e}, trying pickle")
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
            self.logger.error(f"Error loading model from {model_path}: {e}")
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
            self.logger.debug(f"Extracting features from: {binary_path}")
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
                    self.logger.warning(f"PE feature extraction failed: {e}")
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
            self.logger.error(f"Feature extraction error: {e}")
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
            features.append(pe.FILE_HEADER.NumberOfSections)
            features.append(pe.FILE_HEADER.TimeDateStamp)
            features.append(pe.OPTIONAL_HEADER.SizeOfCode)
            features.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
            features.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

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
            self.logger.warning(f"PE feature extraction error: {e}")
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
                    self.logger.warning(f"Feature scaling failed: {e}, using raw features")

            # Make prediction
            prediction = self.model.predict(features)[0]
            
            # Get prediction probability if available
            probability = None
            if hasattr(self.model, 'predict_proba'):
                try:
                    probabilities = self.model.predict_proba(features)[0]
                    probability = float(max(probabilities))
                except Exception as e:
                    self.logger.warning(f"Probability calculation failed: {e}")

            # Get feature importance if available
            feature_importance = None
            if hasattr(self.model, 'feature_importances_'):
                try:
                    feature_importance = self.model.feature_importances_.tolist()
                except Exception as e:
                    self.logger.warning(f"Feature importance extraction failed: {e}")

            result = {
                'prediction': int(prediction),
                'probability': probability,
                'feature_importance': feature_importance,
                'model_type': type(self.model).__name__,
                'feature_count': features.shape[1]
            }

            self.logger.info(f"Vulnerability prediction: {prediction} (probability: {probability})")
            return result

        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
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
            self.logger.error(f"Model training error: {e}")
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

            self.logger.info(f"Model saved to: {model_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving model to {model_path}: {e}")
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


# Export main class
__all__ = ['MLVulnerabilityPredictor']