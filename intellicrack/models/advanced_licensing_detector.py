#!/usr/bin/env python3
"""
Advanced Licensing Protection Detector - Complete ML Pipeline Replacement

This module replaces the entire old ML model system with a state-of-the-art
streaming-based protection detection system. No local binary storage required.
"""

import os
import io
import json
import time
import hashlib
import requests
import numpy as np
import joblib
import logging
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ML imports
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Optional advanced ML libraries
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    lgb = None
    LIGHTGBM_AVAILABLE = False

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    xgb = None
    XGBOOST_AVAILABLE = False

# Binary analysis imports
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class ProtectionScheme:
    """Protection scheme definition"""
    name: str
    category: str
    signatures: List[str]
    api_patterns: List[str]
    file_patterns: List[str]
    confidence_threshold: float = 0.7


class StreamingFeatureExtractor:
    """Extract features from binary streams without local storage"""
    
    def __init__(self):
        # Protection scheme definitions
        self.protection_schemes = {
            # Hardware-based
            'sentinel_hasp': ProtectionScheme(
                'Sentinel HASP',
                'hardware_dongle',
                ['HASP', 'Sentinel', 'aksusbd', 'hasplms'],
                ['hasp_login', 'hasp_encrypt', 'hasp_decrypt', 'hasp_get_info'],
                ['hasp_rt.exe', 'hasplms.exe', 'aksusbd.sys'],
            ),
            'flexlm': ProtectionScheme(
                'FlexLM/FlexNet',
                'network_license',
                ['FLEXlm', 'lmgrd', 'FEATURE', 'INCREMENT', 'flexnet'],
                ['lc_checkout', 'lc_checkin', 'lc_init', 'lmgrd'],
                ['license.dat', 'license.lic', 'lmgrd.exe'],
            ),
            'codemeter': ProtectionScheme(
                'CodeMeter',
                'hardware_dongle',
                ['CodeMeter', 'CmDongle', 'WIBU', 'CmActLicense'],
                ['CmAccess', 'CmCrypt', 'CmGetLicenseInfo', 'CmRelease'],
                ['CodeMeter.exe', 'WibuCm32.dll', 'WibuCm64.dll'],
            ),
            
            # Software-based
            'winlicense': ProtectionScheme(
                'WinLicense/Themida',
                'software_protection',
                ['WinLicense', 'Themida', 'SecureEngine', 'Oreans'],
                ['SECheckProtection', 'SEDecryptStr', 'SEGetRegistrationName'],
                ['SecureEngine.dll', 'WinLicense.dll'],
            ),
            'vmprotect': ProtectionScheme(
                'VMProtect',
                'virtualization',
                ['VMProtect', '.vmp', 'VMProtectBegin', 'VMProtectEnd'],
                ['VMProtectIsDebuggerPresent', 'VMProtectIsVirtualMachinePresent'],
                ['VMProtectSDK32.dll', 'VMProtectSDK64.dll'],
            ),
            
            # Gaming DRM
            'steam_ceg': ProtectionScheme(
                'Steam CEG',
                'gaming_drm',
                ['Steam', 'CEG', 'steam_api', 'SteamClient'],
                ['SteamAPI_Init', 'SteamAPI_RestartAppIfNecessary', 'SteamUser'],
                ['steam_api.dll', 'steam_api64.dll', 'steamclient.dll'],
            ),
            'denuvo': ProtectionScheme(
                'Denuvo',
                'gaming_drm',
                ['denuvo', '.denuvo', 'uplay_r1_loader'],
                ['uwp_', 'denuvo_'],  # Obfuscated APIs
                ['uplay_r1_loader.dll', 'uplay_r1_loader64.dll'],
            ),
            
            # Enterprise
            'microsoft_activation': ProtectionScheme(
                'Microsoft Activation',
                'enterprise',
                ['Software\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform'],
                ['SLGetWindowsInformation', 'SLActivateProduct', 'SLGetLicensingStatusInformation'],
                ['slmgr.vbs', 'sppsvc.exe'],
            ),
        }
        
        # Initialize disassembler if available
        if CAPSTONE_AVAILABLE:
            self.cs_x86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.cs_x64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        # Feature categories
        self.feature_categories = [
            'file_characteristics',
            'pe_structure',
            'imports',
            'strings',
            'code_patterns',
            'protection_indicators',
            'crypto_signatures',
            'network_patterns',
            'anti_analysis'
        ]
    
    def extract_from_stream(self, binary_stream: Union[bytes, io.BytesIO]) -> Dict[str, float]:
        """Extract all features from a binary stream"""
        if isinstance(binary_stream, bytes):
            stream = io.BytesIO(binary_stream)
        else:
            stream = binary_stream
            
        features = {}
        
        # Get binary data
        data = stream.read()
        stream.seek(0)
        
        # Basic file characteristics
        features.update(self._extract_file_features(data))
        
        # PE analysis if applicable
        if data[:2] == b'MZ':
            features.update(self._extract_pe_features(stream))
            stream.seek(0)
        
        # String analysis
        features.update(self._extract_string_features(data))
        
        # Code pattern analysis
        if CAPSTONE_AVAILABLE:
            features.update(self._extract_code_patterns(data))
        
        # Protection scheme detection
        features.update(self._detect_protection_schemes(data, features))
        
        # Calculate composite scores
        features['protection_complexity'] = self._calculate_protection_complexity(features)
        features['licensing_confidence'] = self._calculate_licensing_confidence(features)
        
        return features
    
    def _extract_file_features(self, data: bytes) -> Dict[str, float]:
        """Extract basic file characteristics"""
        features = {
            'file_size': len(data),
            'file_entropy': self._calculate_entropy(data),
            'is_pe': float(data[:2] == b'MZ'),
            'is_elf': float(data[:4] == b'\x7fELF'),
            'is_macho': float(data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']),
        }
        
        # Compression/packing indicators
        features['high_entropy'] = float(features['file_entropy'] > 7.0)
        features['has_overlay'] = 0.0  # Will be set in PE analysis
        
        return features
    
    def _extract_pe_features(self, stream: io.BytesIO) -> Dict[str, float]:
        """Extract PE-specific features"""
        features = defaultdict(float)
        
        if not PEFILE_AVAILABLE:
            return features
        
        try:
            pe = pefile.PE(data=stream.read())
            
            # Section analysis
            features['section_count'] = len(pe.sections)
            exec_sections = 0
            high_entropy_sections = 0
            
            for section in pe.sections:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    exec_sections += 1
                
                section_data = section.get_data()
                if len(section_data) > 0:
                    entropy = self._calculate_entropy(section_data)
                    if entropy > 7.0:
                        high_entropy_sections += 1
            
            features['executable_sections'] = exec_sections
            features['high_entropy_sections'] = high_entropy_sections
            
            # Import analysis
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_categories = defaultdict(int)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    
                    # Categorize imports
                    if 'kernel32' in dll_name:
                        category = 'system'
                    elif 'advapi32' in dll_name or 'crypt' in dll_name:
                        category = 'crypto'
                    elif 'ws2_32' in dll_name or 'wininet' in dll_name:
                        category = 'network'
                    elif 'user32' in dll_name or 'gdi32' in dll_name:
                        category = 'ui'
                    else:
                        category = 'other'
                    
                    import_categories[category] += len(entry.imports)
                
                for category, count in import_categories.items():
                    features[f'imports_{category}'] = count
            
            # Resource analysis
            features['has_resources'] = float(hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'))
            
            # Digital signature
            has_sig = False
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                dir_security = getattr(pe, 'DIRECTORY_ENTRY_SECURITY', None)
                if dir_security and hasattr(dir_security, 'VirtualAddress'):
                    has_sig = dir_security.VirtualAddress != 0
            features['has_signature'] = float(has_sig)
            
            # TLS callbacks (anti-debugging indicator)
            features['has_tls'] = float(hasattr(pe, 'DIRECTORY_ENTRY_TLS'))
            
            # Overlay detection
            features['has_overlay'] = float(pe.get_overlay_data_start_offset() is not None)
            
            pe.close()
            
        except Exception as e:
            logger.debug(f"PE parsing error: {e}")
        
        return dict(features)
    
    def _extract_string_features(self, data: bytes) -> Dict[str, float]:
        """Extract string-based features"""
        features = defaultdict(float)
        
        # Extract ASCII strings
        import re
        ascii_strings = re.findall(b'[\x20-\x7E]{4,}', data)
        text = b' '.join(ascii_strings).decode('utf-8', errors='ignore').lower()
        
        # Protection-related keywords
        protection_keywords = {
            'license': ['license', 'licence', 'serial', 'activation', 'registration'],
            'protection': ['protect', 'guard', 'shield', 'secure', 'lock'],
            'crypto': ['crypt', 'encrypt', 'decrypt', 'hash', 'signature'],
            'hardware': ['dongle', 'hardware', 'device', 'usb', 'hasp'],
            'time': ['trial', 'expire', 'days', 'evaluation', 'demo'],
            'network': ['server', 'validate', 'check', 'verify', 'auth'],
        }
        
        for category, keywords in protection_keywords.items():
            count = sum(1 for keyword in keywords if keyword in text)
            features[f'strings_{category}'] = count
        
        # Check for specific protection scheme strings
        for scheme_id, scheme in self.protection_schemes.items():
            scheme_count = sum(1 for sig in scheme.signatures 
                             if sig.lower() in text)
            features[f'strings_scheme_{scheme_id}'] = scheme_count
        
        # License key patterns
        license_patterns = [
            r'[A-Z0-9]{4,6}-[A-Z0-9]{4,6}-[A-Z0-9]{4,6}',  # XXXX-XXXX-XXXX
            r'[A-Z0-9]{25}',  # 25-char keys
            r'[A-F0-9]{32}',  # MD5
            r'[A-F0-9]{40}',  # SHA1
            r'[A-F0-9]{64}',  # SHA256
        ]
        
        for pattern in license_patterns:
            if re.search(pattern.encode(), data, re.IGNORECASE):
                features['has_license_pattern'] += 1
        
        return dict(features)
    
    def _extract_code_patterns(self, data: bytes) -> Dict[str, float]:
        """Extract code-level patterns using disassembly"""
        features = defaultdict(float)
        
        if not CAPSTONE_AVAILABLE or len(data) < 100:
            return features
        
        # Try to find code sections
        # Simple heuristic: look for common function prologues
        prologue_patterns = [
            b'\x55\x8b\xec',  # push ebp; mov ebp, esp (x86)
            b'\x55\x48\x89\xe5',  # push rbp; mov rbp, rsp (x64)
            b'\x48\x89\x5c\x24',  # mov [rsp+...], rbx (x64 Windows)
        ]
        
        code_offset = -1
        for pattern in prologue_patterns:
            offset = data.find(pattern)
            if offset != -1:
                code_offset = offset
                break
        
        if code_offset == -1:
            return features
        
        # Disassemble a sample of code
        code_sample = data[code_offset:code_offset + 10000]
        
        # Detect architecture (simplified)
        is_x64 = b'\x48' in code_sample[:100]  # REX prefix common in x64
        cs = self.cs_x64 if is_x64 else self.cs_x86
        
        # Analyze instructions
        anti_debug_count = 0
        crypto_instruction_count = 0
        suspicious_api_count = 0
        
        for i in cs.disasm(code_sample, 0):
            # Anti-debugging
            if i.mnemonic in ['int3', 'int'] and i.op_str == '3':
                anti_debug_count += 1
            elif i.mnemonic == 'rdtsc':  # Timing checks
                anti_debug_count += 1
            
            # Crypto instructions
            if i.mnemonic in ['aesenc', 'aesdec', 'sha256msg1', 'sha256msg2']:
                crypto_instruction_count += 1
            
            # Suspicious API calls
            if i.mnemonic == 'call' and 'IsDebuggerPresent' in str(i.op_str):
                suspicious_api_count += 1
        
        features['anti_debug_instructions'] = anti_debug_count
        features['crypto_instructions'] = crypto_instruction_count
        features['suspicious_api_calls'] = suspicious_api_count
        
        return dict(features)
    
    def _detect_protection_schemes(self, data: bytes, existing_features: Dict) -> Dict[str, float]:
        """Detect specific protection schemes"""
        features = {}
        
        for scheme_id, scheme in self.protection_schemes.items():
            score = 0.0
            max_score = 0.0
            
            # Check signatures
            for sig in scheme.signatures:
                max_score += 1.0
                if sig.encode() in data or sig.lower().encode() in data:
                    score += 1.0
            
            # Check API patterns
            for api in scheme.api_patterns:
                max_score += 0.5
                if api.encode() in data:
                    score += 0.5
            
            # Check file patterns
            for file_pat in scheme.file_patterns:
                max_score += 0.3
                if file_pat.encode() in data:
                    score += 0.3
            
            # Normalize score
            if max_score > 0:
                features[f'scheme_{scheme_id}_score'] = score / max_score
            else:
                features[f'scheme_{scheme_id}_score'] = 0.0
            
            # Set primary protection if above threshold
            if features[f'scheme_{scheme_id}_score'] > scheme.confidence_threshold:
                features[f'protection_category_{scheme.category}'] = 1.0
        
        return features
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        # Count byte occurrences
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts.values():
            if count > 0:
                freq = count / data_len
                entropy -= freq * np.log2(freq)
        
        return entropy
    
    def _calculate_protection_complexity(self, features: Dict) -> float:
        """Calculate overall protection complexity score"""
        complexity = 0.0
        
        # High entropy indicates packing/encryption
        if features.get('high_entropy', 0) > 0:
            complexity += 0.2
        
        # Multiple protection schemes
        protection_count = sum(1 for k, v in features.items() 
                             if k.startswith('scheme_') and v > 0.5)
        complexity += min(protection_count * 0.1, 0.3)
        
        # Anti-analysis features
        if features.get('anti_debug_instructions', 0) > 0:
            complexity += 0.2
        
        if features.get('has_tls', 0) > 0:
            complexity += 0.1
        
        # Code obfuscation
        if features.get('high_entropy_sections', 0) > 1:
            complexity += 0.2
        
        return min(complexity, 1.0)
    
    def _calculate_licensing_confidence(self, features: Dict) -> float:
        """Calculate confidence that binary has licensing protection"""
        confidence = 0.0
        
        # String indicators
        license_strings = features.get('strings_license', 0)
        if license_strings > 0:
            confidence += min(license_strings * 0.1, 0.3)
        
        # Known protection scheme
        max_scheme_score = max(
            (v for k, v in features.items() if k.startswith('scheme_')),
            default=0
        )
        confidence += max_scheme_score * 0.4
        
        # Crypto usage
        if features.get('imports_crypto', 0) > 0:
            confidence += 0.1
        
        # Network validation
        if features.get('imports_network', 0) > 0:
            confidence += 0.1
        
        # Time checks (trial software)
        if features.get('strings_time', 0) > 0:
            confidence += 0.1
        
        return min(confidence, 1.0)


class AdvancedLicensingDetector:
    """Main class for advanced licensing detection with streaming training"""
    
    def __init__(self):
        self.feature_extractor = StreamingFeatureExtractor()
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_names = None
        self.model_path = os.path.join(os.path.dirname(__file__), 'advanced_licensing_model.joblib')
        self.metadata_path = os.path.join(os.path.dirname(__file__), 'advanced_licensing_metadata.json')
        
        # Training configuration
        self.training_config = {
            'batch_size': 100,
            'max_concurrent_downloads': 5,
            'feature_cache_size': 10000,
            'validation_split': 0.2,
            'random_state': 42
        }
    
    def train_from_urls(self, binary_urls: List[str], labels: Optional[List[int]] = None,
                       progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """Train model from URLs using streaming approach"""
        logger.info(f"Starting streaming training with {len(binary_urls)} URLs")
        
        # Feature cache for batch processing
        feature_cache = []
        label_cache = []
        
        # Process URLs in parallel
        with ThreadPoolExecutor(max_workers=self.training_config['max_concurrent_downloads']) as executor:
            # Submit all download tasks
            future_to_url = {}
            for i, url in enumerate(binary_urls):
                future = executor.submit(self._process_single_url, url)
                future_to_url[future] = (url, labels[i] if labels else None)
            
            # Process completed downloads
            completed = 0
            for future in as_completed(future_to_url):
                url, label = future_to_url[future]
                
                try:
                    features = future.result()
                    if features:
                        feature_cache.append(features)
                        if label is not None:
                            label_cache.append(label)
                        else:
                            # Auto-label based on features
                            label_cache.append(self._auto_label(features))
                        
                        # Process batch when cache is full
                        if len(feature_cache) >= self.training_config['batch_size']:
                            self._process_batch(feature_cache, label_cache)
                            feature_cache = []
                            label_cache = []
                    
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(binary_urls))
        
        # Process remaining features
        if feature_cache:
            self._process_batch(feature_cache, label_cache)
        
        # Train final models
        return self._train_final_models()
    
    def _process_single_url(self, url: str) -> Optional[Dict[str, float]]:
        """Download and extract features from a single URL"""
        try:
            # Download with timeout
            response = requests.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Read in chunks to avoid memory issues
            chunks = []
            size = 0
            max_size = 100 * 1024 * 1024  # 100MB limit
            
            for chunk in response.iter_content(chunk_size=8192):
                chunks.append(chunk)
                size += len(chunk)
                if size > max_size:
                    logger.warning(f"File too large, truncating: {url}")
                    break
            
            # Extract features from binary data
            binary_data = b''.join(chunks)
            features = self.feature_extractor.extract_from_stream(binary_data)
            
            # Add URL metadata
            features['url_domain'] = urlparse(url).netloc
            
            return features
            
        except Exception as e:
            logger.error(f"Failed to process URL {url}: {e}")
            return None
    
    def _auto_label(self, features: Dict[str, float]) -> int:
        """Automatically determine label based on features"""
        # Multi-class labeling based on detected protection
        protection_scores = {
            k.replace('scheme_', '').replace('_score', ''): v 
            for k, v in features.items() 
            if k.startswith('scheme_') and k.endswith('_score')
        }
        
        if not protection_scores:
            return 0  # No protection
        
        # Find highest scoring protection
        best_protection = max(protection_scores.items(), key=lambda x: x[1])
        
        # Map to class labels
        protection_to_class = {
            'sentinel_hasp': 1,
            'flexlm': 2,
            'codemeter': 3,
            'winlicense': 4,
            'vmprotect': 5,
            'steam_ceg': 6,
            'denuvo': 7,
            'microsoft_activation': 8,
        }
        
        if best_protection[1] > 0.7:  # High confidence
            return protection_to_class.get(best_protection[0], 9)  # 9 = other
        else:
            return 0  # No clear protection
    
    def _process_batch(self, features: List[Dict], labels: List[int]):
        """Process a batch of features for incremental training"""
        # Convert to numpy array
        if self.feature_names is None:
            self.feature_names = sorted(features[0].keys())
        
        X = np.array([[f.get(name, 0) for name in self.feature_names] 
                      for f in features])
        y = np.array(labels)
        
        # Store for final training
        if not hasattr(self, 'X_train'):
            self.X_train = X
            self.y_train = y
        else:
            self.X_train = np.vstack([self.X_train, X])
            self.y_train = np.hstack([self.y_train, y])
    
    def _train_final_models(self) -> Dict[str, Any]:
        """Train the final ensemble models"""
        logger.info("Training final models...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            self.X_train, self.y_train,
            test_size=self.training_config['validation_split'],
            random_state=self.training_config['random_state'],
            stratify=self.y_train
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        # Train multiple models
        self.models = {}
        
        # Only add models if their libraries are available
        if LIGHTGBM_AVAILABLE:
            self.models['lightgbm'] = self._train_lightgbm(X_train_scaled, y_train)
        if XGBOOST_AVAILABLE:
            self.models['xgboost'] = self._train_xgboost(X_train_scaled, y_train)
        
        # Always include random forest (sklearn is required)
        self.models['random_forest'] = self._train_random_forest(X_train_scaled, y_train)
        
        # Evaluate ensemble
        predictions = {}
        for name, model in self.models.items():
            predictions[name] = model.predict(X_val_scaled)
        
        # Majority voting
        ensemble_pred = np.array([
            np.bincount([predictions[m][i] for m in predictions]).argmax()
            for i in range(len(X_val))
        ])
        
        # Calculate metrics
        report = classification_report(y_val, ensemble_pred, output_dict=True)
        
        # Save model and metadata
        self._save_model(report)
        
        return {
            'accuracy': report['accuracy'],
            'classes': len(set(y_train)),
            'samples': len(self.X_train),
            'features': len(self.feature_names),
            'report': report
        }
    
    def _train_lightgbm(self, X: np.ndarray, y: np.ndarray):
        """Train LightGBM model"""
        if not LIGHTGBM_AVAILABLE:
            raise ImportError("LightGBM is not installed")
        model = lgb.LGBMClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=10,
            num_leaves=31,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X, y)
        return model
    
    def _train_xgboost(self, X: np.ndarray, y: np.ndarray):
        """Train XGBoost model"""
        if not XGBOOST_AVAILABLE:
            raise ImportError("XGBoost is not installed")
        model = xgb.XGBClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X, y)
        return model
    
    def _train_random_forest(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
        """Train Random Forest model"""
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X, y)
        return model
    
    def predict(self, binary_path_or_url: str) -> Dict[str, Any]:
        """Predict protection type for a binary"""
        # Extract features
        if binary_path_or_url.startswith(('http://', 'https://')):
            features = self._process_single_url(binary_path_or_url)
        else:
            with open(binary_path_or_url, 'rb') as f:
                features = self.feature_extractor.extract_from_stream(f)
        
        if not features:
            return {'error': 'Failed to extract features'}
        
        # Prepare feature vector
        X = np.array([[features.get(name, 0) for name in self.feature_names]])
        X_scaled = self.scaler.transform(X)
        
        # Get predictions from all models
        predictions = {}
        probabilities = {}
        
        for name, model in self.models.items():
            pred = model.predict(X_scaled)[0]
            prob = model.predict_proba(X_scaled)[0]
            predictions[name] = int(pred)
            probabilities[name] = prob.tolist()
        
        # Ensemble prediction
        ensemble_pred = np.bincount(list(predictions.values())).argmax()
        
        # Map prediction to protection type
        class_to_protection = {
            0: "No Protection",
            1: "Sentinel HASP",
            2: "FlexLM/FlexNet",
            3: "CodeMeter",
            4: "WinLicense/Themida",
            5: "VMProtect",
            6: "Steam CEG",
            7: "Denuvo",
            8: "Microsoft Activation",
            9: "Unknown/Custom"
        }
        
        protection_type = class_to_protection.get(ensemble_pred, "Unknown")
        
        # Get confidence
        avg_confidence = np.mean([
            probabilities[name][ensemble_pred] 
            for name in probabilities
        ])
        
        # Determine bypass difficulty
        complexity = features.get('protection_complexity', 0)
        if complexity > 0.8:
            bypass_difficulty = "Very High"
        elif complexity > 0.6:
            bypass_difficulty = "High"
        elif complexity > 0.4:
            bypass_difficulty = "Medium"
        elif complexity > 0.2:
            bypass_difficulty = "Low"
        else:
            bypass_difficulty = "Trivial"
        
        return {
            'protection_type': protection_type,
            'confidence': float(avg_confidence),
            'bypass_difficulty': bypass_difficulty,
            'protection_category': self._get_protection_category(ensemble_pred),
            'detailed_scores': {
                scheme_id: features.get(f'scheme_{scheme_id}_score', 0)
                for scheme_id in self.feature_extractor.protection_schemes
            },
            'model_predictions': predictions,
            'features_summary': {
                'file_size': features.get('file_size', 0),
                'entropy': features.get('file_entropy', 0),
                'has_packing': bool(features.get('high_entropy', 0)),
                'has_anti_debug': bool(features.get('anti_debug_instructions', 0)),
                'protection_complexity': complexity
            }
        }
    
    def _get_protection_category(self, class_id: int) -> str:
        """Get protection category from class ID"""
        categories = {
            0: "none",
            1: "hardware_dongle",
            2: "network_license",
            3: "hardware_dongle",
            4: "software_protection",
            5: "virtualization",
            6: "gaming_drm",
            7: "gaming_drm",
            8: "enterprise",
            9: "custom"
        }
        return categories.get(class_id, "unknown")
    
    def _save_model(self, report: Dict):
        """Save trained model and metadata"""
        # Save models, scaler, and feature names
        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'protection_schemes': self.feature_extractor.protection_schemes
        }
        
        joblib.dump(model_data, self.model_path, compress=3)
        
        # Save metadata
        metadata = {
            'version': '2.0',
            'trained_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'features': len(self.feature_names),
            'protection_types': 10,
            'accuracy': report['accuracy'],
            'samples_trained': len(self.X_train),
            'model_size_mb': os.path.getsize(self.model_path) / 1024 / 1024
        }
        
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {self.model_path}")
        logger.info(f"Model size: {metadata['model_size_mb']:.2f} MB")
    
    def load_model(self) -> bool:
        """Load trained model"""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model not found at {self.model_path}")
                return False
            
            model_data = joblib.load(self.model_path)
            self.models = model_data['models']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            
            # Load metadata
            if os.path.exists(self.metadata_path):
                with open(self.metadata_path, 'r') as f:
                    metadata = json.load(f)
                logger.info(f"Loaded model v{metadata['version']} "
                          f"(accuracy: {metadata['accuracy']:.2%})")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False


# Backward compatibility wrapper
class IntellicrackMLPredictor:
    """Compatibility wrapper for existing code"""
    
    def __init__(self):
        self.detector = AdvancedLicensingDetector()
        self.model_loaded = False
    
    def load_model(self) -> bool:
        """Load the model"""
        self.model_loaded = self.detector.load_model()
        return self.model_loaded
    
    def predict_vulnerability(self, binary_path: str) -> Dict[str, Any]:
        """Predict vulnerability (wrapped as protection detection)"""
        if not self.model_loaded:
            if not self.load_model():
                return {
                    'success': False,
                    'error': 'Model not loaded'
                }
        
        try:
            result = self.detector.predict(binary_path)
            
            # Convert to old format for compatibility
            return {
                'success': True,
                'binary_path': binary_path,
                'prediction': 'vulnerable' if result['confidence'] > 0.5 else 'secure',
                'probability': result['confidence'],
                'vulnerability_type': result['protection_type'],
                'confidence': 'high' if result['confidence'] > 0.8 else 'medium',
                'features': result['features_summary'],
                'recommendations': [
                    f"Protection detected: {result['protection_type']}",
                    f"Bypass difficulty: {result['bypass_difficulty']}",
                    f"Category: {result['protection_category']}"
                ]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


if __name__ == "__main__":
    # Example usage
    detector = AdvancedLicensingDetector()
    
    # Example training URLs (would be replaced with real URLs)
    training_urls = [
        # These would be real URLs to trial software, demos, etc.
        "https://example.com/software_trial.exe",
        "https://example.com/demo_version.exe",
    ]
    
    # Train model (would take hours with real data)
    # results = detector.train_from_urls(training_urls)
    # print(f"Training complete: {results['accuracy']:.2%} accuracy")
    
    # Load and use existing model
    if detector.load_model():
        # Predict on a binary
        result = detector.predict("/path/to/binary.exe")
        print(f"Protection: {result['protection_type']}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Difficulty: {result['bypass_difficulty']}")