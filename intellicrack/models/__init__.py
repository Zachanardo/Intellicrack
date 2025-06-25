"""
Intellicrack ML Models Package - Advanced Licensing Detection System

This package provides state-of-the-art machine learning models for
software protection and licensing detection.
"""

# Keep original imports for compatibility
from .model_manager import ModelManager

# Import severity levels for backwards compatibility
try:
    from ..utils.analysis.severity_levels import SeverityLevel, VulnerabilityLevel
except ImportError:
    # Fallback enum if severity_levels not available
    from enum import Enum
    class VulnerabilityLevel(Enum):
        """Fallback vulnerability severity levels when module unavailable."""
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"
    SeverityLevel = VulnerabilityLevel

# Import the new ML system
from .ml_integration_v2 import (
    MLSystemV2,
    get_ml_system,
    MLVulnerabilityPredictor,
    IntellicrackMLPredictor
)

from .advanced_licensing_detector import (
    AdvancedLicensingDetector,
    StreamingFeatureExtractor,
    ProtectionScheme
)

from .streaming_training_collector import StreamingTrainingCollector

# Maintain backward compatibility by redirecting old imports
import sys
from types import ModuleType

# Create mock modules for backward compatibility
class MockModule(ModuleType):
    """Mock module that redirects to new system"""
    
    def __init__(self, name):
        super().__init__(name)
        self.ml_system = get_ml_system()
    
    def __getattr__(self, name):
        # Redirect to new system
        if name == 'IntellicrackMLPredictor':
            return IntellicrackMLPredictor
        elif name == 'MLVulnerabilityPredictor':
            return MLVulnerabilityPredictor
        elif name == 'RobustLicensingTrainer':
            # Return a compatibility wrapper
            class RobustLicensingTrainer:
                def __init__(self, *args, **kwargs):
                    self.ml_system = get_ml_system()
                
                def train_robust_ensemble(self, *args, **kwargs):
                    return self.ml_system.train_model()
            
            return RobustLicensingTrainer
        elif name == 'LicensingPatternsExtractor':
            return StreamingFeatureExtractor
        else:
            raise AttributeError(f"module has no attribute '{name}'")

# Replace old modules in sys.modules to ensure all imports use new system
old_modules = [
    'intellicrack.models.ml_integration',
    'intellicrack.models.robust_licensing_trainer',
    'intellicrack.models.licensing_patterns_extractor',
    'intellicrack.models.focused_licensing_collector'
]

for module_name in old_modules:
    if module_name in sys.modules:
        # Replace with mock that redirects to new system
        sys.modules[module_name] = MockModule(module_name)

# Export main interface
__all__ = [
    'ModelManager',
    'VulnerabilityLevel',
    'SeverityLevel',
    'MLSystemV2',
    'get_ml_system',
    'MLVulnerabilityPredictor',
    'IntellicrackMLPredictor',
    'AdvancedLicensingDetector',
    'StreamingFeatureExtractor',
    'StreamingTrainingCollector',
    'ProtectionScheme'
]

# Initialize the ML system on import
_ml_system = get_ml_system()

def get_current_model_info():
    """Get information about the current ML model"""
    status = _ml_system.get_training_status()
    return {
        'type': 'Advanced Licensing Detector v2.0',
        'loaded': status['model_loaded'],
        'exists': status['model_exists'],
        'size_mb': status['model_size_mb'],
        'capabilities': [
            'Multi-class protection classification',
            'Streaming training (no local storage)',
            '50+ protection scheme detection',
            'Obfuscation handling',
            'Real-time analysis'
        ]
    }

# Log initialization
import logging
logger = logging.getLogger(__name__)
logger.info("Advanced ML system initialized")
model_info = get_current_model_info()
if model_info['loaded']:
    logger.info(f"Model loaded: {model_info['size_mb']:.2f} MB")
else:
    logger.info("No model loaded - training required")
