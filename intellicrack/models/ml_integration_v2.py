#!/usr/bin/env python3
"""
ML Integration v2 - Complete Replacement for Old ML System

This module provides the integration layer that replaces all old ML components
with the new advanced licensing detection system.
"""

import os
import logging
import time
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import threading
import queue

from .advanced_licensing_detector import AdvancedLicensingDetector
from .streaming_training_collector import StreamingTrainingCollector

logger = logging.getLogger(__name__)


class MLSystemV2:
    """
    Complete ML system replacement with streaming training and advanced detection.
    
    This class replaces:
    - ml_predictor.py
    - ml_predictor_updated.py
    - ml_integration.py
    - robust_licensing_trainer.py
    - licensing_patterns_extractor.py
    """
    
    def __init__(self):
        self.detector = AdvancedLicensingDetector()
        self.collector = StreamingTrainingCollector()
        self.model_loaded = False
        self.training_in_progress = False
        self.training_thread = None
        self.training_queue = queue.Queue()
        
        # Paths
        self.model_dir = Path(__file__).parent
        self.model_path = self.model_dir / "advanced_licensing_model.joblib"
        self.metadata_path = self.model_dir / "advanced_licensing_metadata.json"
        self.training_urls_path = self.model_dir / "training_urls.json"
        
        # Try to load existing model
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize model - load if exists, otherwise prepare for training"""
        if self.model_path.exists():
            logger.info("Loading existing advanced model...")
            self.model_loaded = self.detector.load_model()
            if self.model_loaded:
                logger.info("Advanced licensing model loaded successfully")
            else:
                logger.warning("Failed to load model, training required")
        else:
            logger.info("No existing model found, training required")
    
    def predict(self, binary_path_or_url: str) -> Dict[str, Any]:
        """
        Predict protection type for a binary.
        
        This replaces:
        - predict_vulnerability()
        - analyze_binary()
        - detect_protection()
        """
        if not self.model_loaded:
            return {
                'success': False,
                'error': 'Model not loaded. Please train the model first.',
                'protection_type': 'Unknown',
                'confidence': 0.0
            }
        
        try:
            result = self.detector.predict(binary_path_or_url)
            
            # Add success flag for compatibility
            result['success'] = True
            
            # Add vulnerability assessment based on protection
            if result['protection_type'] != 'No Protection':
                result['has_protection'] = True
                result['vulnerability_score'] = 1.0 - result['confidence']
            else:
                result['has_protection'] = False
                result['vulnerability_score'] = 0.9  # Unprotected = vulnerable
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'success': False,
                'error': str(e),
                'protection_type': 'Error',
                'confidence': 0.0
            }
    
    def train_model(self, progress_callback: Optional[Callable] = None,
                   use_cached_urls: bool = True) -> Dict[str, Any]:
        """
        Train the model using streaming approach.
        
        This replaces the old training pipeline with efficient streaming.
        """
        if self.training_in_progress:
            return {
                'success': False,
                'error': 'Training already in progress'
            }
        
        # Start training in background thread
        self.training_thread = threading.Thread(
            target=self._training_worker,
            args=(progress_callback, use_cached_urls)
        )
        self.training_thread.start()
        
        return {
            'success': True,
            'message': 'Training started in background'
        }
    
    def _training_worker(self, progress_callback: Optional[Callable],
                        use_cached_urls: bool):
        """Background training worker"""
        self.training_in_progress = True
        
        try:
            # Collect or load URLs
            if use_cached_urls and self.training_urls_path.exists():
                logger.info("Loading cached training URLs...")
                import json
                with open(self.training_urls_path, 'r') as f:
                    url_data = json.load(f)
                urls = url_data['urls']
            else:
                logger.info("Collecting fresh training URLs...")
                urls = self.collector.collect_all_urls(target_count=5000)
                
                # Save for future use
                self.collector.save_url_dataset(urls, str(self.training_urls_path))
            
            # Create labeled dataset
            training_urls, training_labels = self.collector.create_labeled_dataset(urls)
            
            logger.info(f"Starting training with {len(training_urls)} URLs")
            
            # Train model with streaming
            result = self.detector.train_from_urls(
                training_urls,
                training_labels,
                progress_callback=progress_callback
            )
            
            # Update model status
            if result['accuracy'] > 0.9:
                self.model_loaded = True
                logger.info(f"Training completed successfully: {result['accuracy']:.2%} accuracy")
            else:
                logger.warning(f"Training completed with low accuracy: {result['accuracy']:.2%}")
            
            # Notify completion
            if progress_callback:
                progress_callback(len(training_urls), len(training_urls), result)
            
        except Exception as e:
            logger.error(f"Training error: {e}")
            if progress_callback:
                progress_callback(-1, -1, {'error': str(e)})
        
        finally:
            self.training_in_progress = False
    
    def get_training_status(self) -> Dict[str, Any]:
        """Get current training status"""
        return {
            'in_progress': self.training_in_progress,
            'model_loaded': self.model_loaded,
            'model_exists': self.model_path.exists(),
            'model_size_mb': self.model_path.stat().st_size / 1024 / 1024 if self.model_path.exists() else 0
        }
    
    def analyze_batch(self, binary_paths: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple binaries efficiently"""
        results = []
        
        for path in binary_paths:
            result = self.predict(path)
            result['file_path'] = path
            results.append(result)
        
        return results
    
    def get_protection_info(self, protection_type: str) -> Dict[str, Any]:
        """Get detailed information about a protection type"""
        protection_info = {
            "No Protection": {
                "description": "No licensing protection detected",
                "difficulty": "N/A",
                "common_tools": [],
                "bypass_methods": ["N/A"]
            },
            "Sentinel HASP": {
                "description": "Hardware dongle-based protection by Thales",
                "difficulty": "High",
                "common_tools": ["Sentinel HASP emulator", "Dumper tools"],
                "bypass_methods": ["Dongle emulation", "Driver hooking", "Memory patching"]
            },
            "FlexLM/FlexNet": {
                "description": "Network floating license manager by Flexera",
                "difficulty": "Medium",
                "common_tools": ["FlexLM crack tools", "License generators"],
                "bypass_methods": ["License server emulation", "Feature patching", "Date manipulation"]
            },
            "CodeMeter": {
                "description": "Hardware and software protection by Wibu-Systems",
                "difficulty": "High",
                "common_tools": ["CodeMeter emulator"],
                "bypass_methods": ["CmDongle emulation", "API hooking", "License manipulation"]
            },
            "WinLicense/Themida": {
                "description": "Software protection with virtualization by Oreans",
                "difficulty": "Very High",
                "common_tools": ["Themida unpacker", "OllyDbg", "x64dbg"],
                "bypass_methods": ["VM unpacking", "IAT reconstruction", "Anti-debug bypass"]
            },
            "VMProtect": {
                "description": "Code virtualization and protection",
                "difficulty": "Very High",
                "common_tools": ["VMProtect unpacker", "Devirtualizer"],
                "bypass_methods": ["Devirtualization", "Symbolic execution", "Pattern matching"]
            },
            "Steam CEG": {
                "description": "Steam's Custom Executable Generation",
                "difficulty": "Medium",
                "common_tools": ["Steamless", "Steam emulators"],
                "bypass_methods": ["CEG unwrapping", "Steam API emulation", "Offline patching"]
            },
            "Denuvo": {
                "description": "Anti-tamper gaming protection",
                "difficulty": "Very High",
                "common_tools": ["Specialized Denuvo tools"],
                "bypass_methods": ["VM analysis", "Trigger identification", "Binary patching"]
            },
            "Microsoft Activation": {
                "description": "Windows/Office activation technologies",
                "difficulty": "Medium",
                "common_tools": ["KMS tools", "Activation scripts"],
                "bypass_methods": ["KMS emulation", "Digital license manipulation", "Registry patching"]
            },
            "Unknown/Custom": {
                "description": "Custom or unidentified protection scheme",
                "difficulty": "Variable",
                "common_tools": ["Generic analysis tools"],
                "bypass_methods": ["Manual analysis required", "Pattern identification", "Behavior analysis"]
            }
        }
        
        return protection_info.get(protection_type, protection_info["Unknown/Custom"])
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance from trained model"""
        if not self.model_loaded:
            return {}
        
        try:
            # Get feature importance from LightGBM model
            if 'lightgbm' in self.detector.models:
                model = self.detector.models['lightgbm']
                importance = model.feature_importances_
                
                # Map to feature names
                feature_importance = {
                    name: float(importance[i])
                    for i, name in enumerate(self.detector.feature_names)
                }
                
                # Sort by importance
                return dict(sorted(feature_importance.items(), 
                                 key=lambda x: x[1], reverse=True)[:20])
            
        except Exception as e:
            logger.error(f"Error getting feature importance: {e}")
        
        return {}


# Singleton instance for global access
_ml_system = None


def get_ml_system() -> MLSystemV2:
    """Get or create the ML system singleton"""
    global _ml_system
    if _ml_system is None:
        _ml_system = MLSystemV2()
    return _ml_system


# Compatibility wrappers for old API
class MLVulnerabilityPredictor:
    """Compatibility wrapper for old ml_predictor.py API"""
    
    def __init__(self, model_path: Optional[str] = None):
        self.ml_system = get_ml_system()
    
    def predict_vulnerability(self, binary_path: str) -> Dict[str, Any]:
        """Old API compatibility"""
        result = self.ml_system.predict(binary_path)
        
        # Convert to old format
        return {
            'prediction': 1 if result.get('has_protection', False) else 0,
            'probability': result.get('vulnerability_score', 0.5),
            'confidence': result.get('confidence', 0.0),
            'vulnerability_type': result.get('protection_type', 'Unknown'),
            'recommendations': [
                f"Protection: {result.get('protection_type', 'None')}",
                f"Difficulty: {result.get('bypass_difficulty', 'Unknown')}"
            ]
        }


class IntellicrackMLPredictor:
    """Compatibility wrapper for old ml_integration.py API"""
    
    def __init__(self):
        self.ml_system = get_ml_system()
    
    def load_model(self) -> bool:
        return self.ml_system.model_loaded
    
    def predict_vulnerability(self, binary_path: str) -> Dict[str, Any]:
        result = self.ml_system.predict(binary_path)
        
        return {
            'success': result.get('success', False),
            'binary_path': binary_path,
            'prediction': 'vulnerable' if result.get('vulnerability_score', 0) > 0.5 else 'secure',
            'probability': result.get('vulnerability_score', 0.0),
            'vulnerability_type': result.get('protection_type'),
            'confidence': 'high' if result.get('confidence', 0) > 0.8 else 'medium',
            'features': result.get('features_summary', {}),
            'recommendations': [
                f"Protection: {result.get('protection_type', 'None')}",
                f"Category: {result.get('protection_category', 'unknown')}",
                f"Bypass Difficulty: {result.get('bypass_difficulty', 'Unknown')}"
            ]
        }


if __name__ == "__main__":
    # Example usage
    ml_system = get_ml_system()
    
    # Check status
    status = ml_system.get_training_status()
    print(f"Model status: {status}")
    
    if not status['model_loaded']:
        print("Starting model training...")
        
        def progress_callback(current, total, result=None):
            if result:
                print(f"\nTraining complete: {result}")
            else:
                print(f"\rProgress: {current}/{total} ({current/total*100:.1f}%)", end='')
        
        ml_system.train_model(progress_callback=progress_callback)
        
        # Wait for training to complete
        while ml_system.training_in_progress:
            time.sleep(1)
    
    # Test prediction
    if ml_system.model_loaded:
        result = ml_system.predict("C:/Windows/System32/notepad.exe")
        print(f"\nPrediction result: {result}")