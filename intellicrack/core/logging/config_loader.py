"""
Configuration Loader for Centralized Logging System

This module provides functionality to load configuration from YAML files
and integrate it with the centralized logging system.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .central_config import LogLevel
from .log_monitor import AlertSeverity, LogPattern


class ConfigLoader:
    """Loads and processes logging configuration from various sources."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def load_from_yaml(self, config_path: Path) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            import yaml
            
            if not config_path.exists():
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            self.logger.info(f"Loaded logging configuration from {config_path}")
            return config or {}
            
        except ImportError:
            self.logger.warning("PyYAML not available - cannot load YAML configuration")
            return {}
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_path}: {e}")
            return {}
    
    def load_from_json(self, config_path: Path) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            import json
            
            if not config_path.exists():
                self.logger.warning(f"Configuration file not found: {config_path}")
                return {}
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.logger.info(f"Loaded logging configuration from {config_path}")
            return config
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_path}: {e}")
            return {}
    
    def load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}
        
        # Global settings
        if 'INTELLICRACK_LOG_LEVEL' in os.environ:
            config['global_level'] = os.environ['INTELLICRACK_LOG_LEVEL']
        
        if 'INTELLICRACK_LOG_CONSOLE' in os.environ:
            config['console_enabled'] = os.environ['INTELLICRACK_LOG_CONSOLE'].lower() in ['true', '1', 'yes']
        
        if 'INTELLICRACK_LOG_FILE' in os.environ:
            config['file_enabled'] = os.environ['INTELLICRACK_LOG_FILE'].lower() in ['true', '1', 'yes']
        
        if 'INTELLICRACK_LOG_JSON' in os.environ:
            config['json_format'] = os.environ['INTELLICRACK_LOG_JSON'].lower() in ['true', '1', 'yes']
        
        if 'INTELLICRACK_LOG_DIR' in os.environ:
            config['log_directory'] = os.environ['INTELLICRACK_LOG_DIR']
        
        # Aggregation settings
        if 'INTELLICRACK_LOG_AGGREGATION' in os.environ:
            config['aggregation_enabled'] = os.environ['INTELLICRACK_LOG_AGGREGATION'].lower() in ['true', '1', 'yes']
        
        if 'INTELLICRACK_LOG_EXTERNAL_ENDPOINT' in os.environ:
            config['external_endpoint'] = os.environ['INTELLICRACK_LOG_EXTERNAL_ENDPOINT']
        
        if 'INTELLICRACK_LOG_EXTERNAL_API_KEY' in os.environ:
            config['external_api_key'] = os.environ['INTELLICRACK_LOG_EXTERNAL_API_KEY']
        
        # Performance settings
        if 'INTELLICRACK_PERF_LOGGING' in os.environ:
            config['enable_performance_logging'] = os.environ['INTELLICRACK_PERF_LOGGING'].lower() in ['true', '1', 'yes']
        
        if 'INTELLICRACK_PERF_THRESHOLD' in os.environ:
            try:
                config['performance_threshold_ms'] = int(os.environ['INTELLICRACK_PERF_THRESHOLD'])
            except ValueError:
                pass
        
        if config:
            self.logger.info("Loaded logging configuration from environment variables")
        
        return config
    
    def process_config(self, raw_config: Dict[str, Any], environment: Optional[str] = None) -> Dict[str, Any]:
        """Process raw configuration and apply environment-specific settings."""
        config = {}
        
        # Start with global settings
        if 'global' in raw_config:
            config.update(raw_config['global'])
        
        # Apply environment-specific settings
        env = environment or os.environ.get('INTELLICRACK_ENV', 'development')
        if 'environments' in raw_config and env in raw_config['environments']:
            config.update(raw_config['environments'][env])
        
        # Process module levels
        if 'module_levels' in raw_config:
            module_levels = {}
            for module, level in raw_config['module_levels'].items():
                if isinstance(level, str):
                    module_levels[module] = LogLevel.from_string(level)
                else:
                    module_levels[module] = level
            config['module_levels'] = module_levels
        
        # Process aggregation settings
        if 'aggregation' in raw_config:
            aggregation_config = raw_config['aggregation']
            config.update({
                'aggregation_enabled': aggregation_config.get('enabled', True),
                'aggregation_interval': aggregation_config.get('interval', 300),
                'external_endpoint': aggregation_config.get('external_endpoint'),
                'external_api_key': aggregation_config.get('external_api_key'),
            })
        
        # Process performance settings
        if 'performance' in raw_config:
            perf_config = raw_config['performance']
            config.update({
                'enable_performance_logging': perf_config.get('enabled', True),
                'performance_threshold_ms': perf_config.get('threshold_ms', 1000),
            })
        
        # Process security settings
        if 'security' in raw_config:
            security_config = raw_config['security']
            config.update({
                'enable_security_logging': security_config.get('enabled', True),
                'log_sensitive_operations': security_config.get('log_sensitive_operations', True),
            })
        
        return config
    
    def load_monitoring_patterns(self, raw_config: Dict[str, Any]) -> list:
        """Load monitoring patterns from configuration."""
        patterns = []
        
        if 'monitoring' not in raw_config or 'patterns' not in raw_config['monitoring']:
            return patterns
        
        pattern_configs = raw_config['monitoring']['patterns']
        
        for name, pattern_config in pattern_configs.items():
            try:
                severity = AlertSeverity(pattern_config['severity'].lower())
                pattern = LogPattern(
                    name=name,
                    pattern=pattern_config['pattern'],
                    severity=severity,
                    description=pattern_config.get('description', f'Pattern: {name}'),
                    action=pattern_config.get('action')
                )
                patterns.append(pattern)
            except Exception as e:
                self.logger.warning(f"Failed to load pattern '{name}': {e}")
        
        return patterns
    
    def load_monitoring_thresholds(self, raw_config: Dict[str, Any]) -> Dict[str, float]:
        """Load monitoring thresholds from configuration."""
        thresholds = {}
        
        if 'monitoring' in raw_config and 'thresholds' in raw_config['monitoring']:
            threshold_config = raw_config['monitoring']['thresholds']
            thresholds.update({
                'error_rate': threshold_config.get('error_rate', 0.1),
                'log_rate': threshold_config.get('log_rate', 100),
                'performance': threshold_config.get('performance', 5.0),
            })
        
        return thresholds
    
    def get_default_config_paths(self) -> list:
        """Get list of default configuration file paths to try."""
        current_dir = Path(__file__).parent
        project_root = current_dir.parent.parent.parent
        
        paths = [
            # Local to logging module
            current_dir / "config.yaml",
            current_dir / "config.yml",
            current_dir / "config.json",
            
            # Project root
            project_root / "logging_config.yaml",
            project_root / "logging_config.yml", 
            project_root / "logging_config.json",
            
            # User configuration directory
            Path.home() / ".intellicrack" / "logging.yaml",
            Path.home() / ".intellicrack" / "logging.yml",
            Path.home() / ".intellicrack" / "logging.json",
        ]
        
        # Add system-wide configuration paths
        if os.name == 'nt':  # Windows
            system_config = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'))
            paths.extend([
                system_config / "Intellicrack" / "logging.yaml",
                system_config / "Intellicrack" / "logging.yml",
                system_config / "Intellicrack" / "logging.json",
            ])
        else:  # Unix-like
            paths.extend([
                Path("/etc/intellicrack/logging.yaml"),
                Path("/etc/intellicrack/logging.yml"),
                Path("/etc/intellicrack/logging.json"),
            ])
        
        return paths
    
    def load_configuration(self, config_path: Optional[Path] = None, 
                          environment: Optional[str] = None) -> Dict[str, Any]:
        """Load complete logging configuration."""
        # Start with environment variables
        config = self.load_from_environment()
        
        # Load file configuration
        raw_config = {}
        
        if config_path:
            # Use specified path
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                raw_config = self.load_from_yaml(config_path)
            elif config_path.suffix.lower() == '.json':
                raw_config = self.load_from_json(config_path)
            else:
                self.logger.warning(f"Unsupported configuration file format: {config_path}")
        else:
            # Try default paths
            for path in self.get_default_config_paths():
                if path.exists():
                    self.logger.info(f"Found configuration file: {path}")
                    if path.suffix.lower() in ['.yaml', '.yml']:
                        raw_config = self.load_from_yaml(path)
                    elif path.suffix.lower() == '.json':
                        raw_config = self.load_from_json(path)
                    
                    if raw_config:
                        break
        
        # Process configuration
        if raw_config:
            file_config = self.process_config(raw_config, environment)
            # Environment variables override file configuration
            file_config.update(config)
            config = file_config
        
        return config
    
    def save_configuration(self, config: Dict[str, Any], config_path: Path) -> bool:
        """Save configuration to file."""
        try:
            # Ensure directory exists
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                try:
                    import yaml
                    with open(config_path, 'w', encoding='utf-8') as f:
                        yaml.dump(config, f, default_flow_style=False, indent=2)
                except ImportError:
                    self.logger.error("PyYAML not available - cannot save YAML configuration")
                    return False
            elif config_path.suffix.lower() == '.json':
                import json
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2, default=str)
            else:
                self.logger.error(f"Unsupported configuration file format: {config_path}")
                return False
            
            self.logger.info(f"Saved configuration to {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration to {config_path}: {e}")
            return False


# Global configuration loader instance
config_loader = ConfigLoader()


def load_logging_config(config_path: Optional[Path] = None, 
                       environment: Optional[str] = None) -> Dict[str, Any]:
    """Load logging configuration from file and environment."""
    return config_loader.load_configuration(config_path, environment)


def save_logging_config(config: Dict[str, Any], config_path: Path) -> bool:
    """Save logging configuration to file."""
    return config_loader.save_configuration(config, config_path)


def get_default_config_paths() -> list:
    """Get list of default configuration file paths."""
    return config_loader.get_default_config_paths()


# Export public interface
__all__ = [
    'ConfigLoader',
    'config_loader',
    'load_logging_config',
    'save_logging_config', 
    'get_default_config_paths',
]