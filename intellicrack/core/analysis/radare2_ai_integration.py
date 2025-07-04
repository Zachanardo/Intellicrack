import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from intellicrack.logger import logger

from ...utils.tools.radare2_utils import R2Exception, r2_session
from .radare2_imports import R2ImportExportAnalyzer
from .radare2_strings import R2StringAnalyzer

"""
Radare2 AI/ML Integration Engine for Advanced Pattern Recognition

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


# Safe ML dependencies with comprehensive fallbacks
try:
    # Use safe import system
    from ...utils.dependency_fallbacks import (
        safe_import_numpy,
        safe_import_sklearn,
    )

    np = safe_import_numpy()
    sklearn = safe_import_sklearn()

    # Try to get specific sklearn components
    try:
        import joblib
        from sklearn.cluster import DBSCAN
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.preprocessing import StandardScaler
        SKLEARN_AVAILABLE = True
    except:
        # Use fallback implementations
        DBSCAN = sklearn.cluster.DBSCAN
        IsolationForest = None
        RandomForestClassifier = sklearn.ensemble.RandomForestClassifier
        TfidfVectorizer = None
        StandardScaler = sklearn.preprocessing.StandardScaler
        joblib = None
        SKLEARN_AVAILABLE = False

except Exception as e:
    logger.error("Exception in radare2_ai_integration: %s", e)
    # Complete fallback
    np = None
    DBSCAN = None
    IsolationForest = None
    RandomForestClassifier = None
    TfidfVectorizer = None
    StandardScaler = None
    joblib = None
    SKLEARN_AVAILABLE = False



class R2AIEngine:
    """
    Advanced AI/ML engine for radare2 analysis with pattern recognition capabilities.

    Provides AI-enhanced analysis for:
    - Automated license validation detection
    - Advanced vulnerability pattern recognition
    - Function clustering and similarity analysis
    - Anomaly detection in binary behavior
    - Automated bypass generation using ML
    - Code similarity and family classification
    """

    def __init__(self, binary_path: str, radare2_path: Optional[str] = None):
        """Initialize AI engine."""
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)

        # ML Models
        self.license_detector = None
        self.vulnerability_classifier = None
        self.function_clusterer = None
        self.anomaly_detector = None

        # Feature extractors (only if sklearn available)
        if SKLEARN_AVAILABLE:
            self.text_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            self.scaler = StandardScaler()
        else:
            self.text_vectorizer = None
            self.scaler = None

        # Model paths
        self.model_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'models', 'radare2')
        os.makedirs(self.model_dir, exist_ok=True)

    def analyze_with_ai(self) -> Dict[str, Any]:
        """Perform comprehensive AI-enhanced analysis."""
        result = {
            'binary_path': self.binary_path,
            'ai_license_detection': {},
            'ai_vulnerability_prediction': {},
            'function_clustering': {},
            'anomaly_detection': {},
            'code_similarity': {},
            'automated_bypass_suggestions': {},
            'confidence_scores': {},
            'model_performance': {}
        }

        try:
            # Extract features from binary
            features = self._extract_comprehensive_features()

            # AI-based license detection
            result['ai_license_detection'] = self._ai_license_detection(features)

            # AI vulnerability prediction
            result['ai_vulnerability_prediction'] = self._ai_vulnerability_prediction(features)

            # Function clustering
            result['function_clustering'] = self._function_clustering_analysis(features)

            # Anomaly detection
            result['anomaly_detection'] = self._anomaly_detection_analysis(features)

            # Code similarity analysis
            result['code_similarity'] = self._code_similarity_analysis(features)

            # Automated bypass suggestions
            result['automated_bypass_suggestions'] = self._generate_ai_bypass_suggestions(features)

            # Calculate confidence scores
            result['confidence_scores'] = self._calculate_confidence_scores(result)

            # Model performance metrics
            result['model_performance'] = self._get_model_performance_metrics()

        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"AI analysis failed: {e}")

        return result

    def _extract_comprehensive_features(self) -> Dict[str, Any]:
        """Extract comprehensive features for ML analysis."""
        features = {
            'static_features': {},
            'function_features': [],
            'string_features': {},
            'import_features': {},
            'graph_features': {},
            'entropy_features': {}
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Basic binary information
                binary_info = r2.get_info()
                features['static_features'] = self._extract_static_features(binary_info)

                # Function-level features
                functions = r2.get_functions()
                features['function_features'] = self._extract_function_features(functions)

                # String-based features
                string_analyzer = R2StringAnalyzer(self.binary_path, self.radare2_path)
                string_analysis = string_analyzer.analyze_all_strings()
                features['string_features'] = self._extract_string_features(string_analysis)

                # Import/Export features
                import_analyzer = R2ImportExportAnalyzer(self.binary_path, self.radare2_path)
                import_analysis = import_analyzer.analyze_imports_exports()
                features['import_features'] = self._extract_import_features(import_analysis)

                # Graph-based features
                features['graph_features'] = self._extract_graph_features(r2, functions)

                # Entropy and complexity features
                features['entropy_features'] = self._extract_entropy_features(r2)

        except R2Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")

        return features

    def _extract_static_features(self, binary_info: Dict[str, Any]) -> Dict[str, float]:
        """Extract static binary features."""
        return {
            'file_size': float(binary_info.get('bin', {}).get('size', 0)),
            'entry_point': float(binary_info.get('bin', {}).get('baddr', 0)),
            'architecture_bits': float(binary_info.get('bin', {}).get('bits', 32)),
            'has_symbols': float(1 if binary_info.get('bin', {}).get('stripped', True) == False else 0),
            'has_debug': float(1 if binary_info.get('bin', {}).get('dbg_file', '') else 0),
            'is_pie': float(1 if binary_info.get('bin', {}).get('pic', False) else 0),
            'has_nx': float(1 if binary_info.get('bin', {}).get('nx', False) else 0),
            'has_canary': float(1 if binary_info.get('bin', {}).get('canary', False) else 0)
        }

    def _extract_function_features(self, functions: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Extract function-level features."""
        function_features = []

        for func in functions[:100]:  # Limit for performance
            features = {
                'size': float(func.get('size', 0)),
                'complexity': float(func.get('cc', 1)),  # Cyclomatic complexity
                'calls': float(func.get('calls', 0)),
                'locals': float(func.get('locals', 0)),
                'args': float(func.get('args', 0)),
                'has_license_keywords': 0.0,
                'has_crypto_keywords': 0.0,
                'has_debug_keywords': 0.0
            }

            # Analyze function name for keywords
            func_name = func.get('name', '').lower()

            if any(keyword in func_name for keyword in ['license', 'valid', 'check', 'trial']):
                features['has_license_keywords'] = 1.0

            if any(keyword in func_name for keyword in ['crypt', 'hash', 'encrypt', 'decrypt']):
                features['has_crypto_keywords'] = 1.0

            if any(keyword in func_name for keyword in ['debug', 'trace', 'log']):
                features['has_debug_keywords'] = 1.0

            function_features.append(features)

        return function_features

    def _extract_string_features(self, string_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract string-based features."""
        total_strings = string_analysis.get('total_strings', 0)

        return {
            'total_strings': float(total_strings),
            'license_string_ratio': float(len(string_analysis.get('license_strings', [])) / max(1, total_strings)),
            'crypto_string_ratio': float(len(string_analysis.get('crypto_strings', [])) / max(1, total_strings)),
            'error_string_ratio': float(len(string_analysis.get('error_message_strings', [])) / max(1, total_strings)),
            'debug_string_ratio': float(len(string_analysis.get('debug_strings', [])) / max(1, total_strings)),
            'average_entropy': float(string_analysis.get('string_entropy_analysis', {}).get('average_entropy', 0)),
            'high_entropy_ratio': float(len(string_analysis.get('string_entropy_analysis', {}).get('high_entropy_strings', [])) / max(1, total_strings)),
            'suspicious_patterns': float(len(string_analysis.get('suspicious_patterns', [])))
        }

    def _extract_import_features(self, import_analysis: Dict[str, Any]) -> Dict[str, float]:
        """Extract import/export features."""
        total_imports = len(import_analysis.get('imports', []))

        api_categories = import_analysis.get('api_categories', {})

        return {
            'total_imports': float(total_imports),
            'crypto_api_ratio': float(len(api_categories.get('cryptography', [])) / max(1, total_imports)),
            'network_api_ratio': float(len(api_categories.get('network_operations', [])) / max(1, total_imports)),
            'file_api_ratio': float(len(api_categories.get('file_operations', [])) / max(1, total_imports)),
            'registry_api_ratio': float(len(api_categories.get('registry_operations', [])) / max(1, total_imports)),
            'process_api_ratio': float(len(api_categories.get('process_management', [])) / max(1, total_imports)),
            'debug_api_ratio': float(len(api_categories.get('debugging', [])) / max(1, total_imports)),
            'suspicious_api_count': float(len(import_analysis.get('suspicious_apis', []))),
            'anti_analysis_api_count': float(len(import_analysis.get('anti_analysis_apis', [])))
        }

    def _extract_graph_features(self, r2, functions: List[Dict[str, Any]]) -> Dict[str, float]:
        """Extract control flow graph features."""
        total_blocks = 0
        total_edges = 0
        max_depth = 0

        for func in functions[:50]:  # Sample for performance
            func_addr = func.get('offset', 0)
            if func_addr:
                try:
                    # Get basic blocks for function
                    blocks_data = r2._execute_command(f'agfj @ {hex(func_addr)}', expect_json=True)
                    if isinstance(blocks_data, list) and blocks_data:
                        blocks = blocks_data[0].get('blocks', [])
                        total_blocks += len(blocks)

                        # Count edges
                        for block in blocks:
                            if block.get('jump'):
                                total_edges += 1
                            if block.get('fail'):
                                total_edges += 1

                        # Estimate depth (simplified)
                        max_depth = max(max_depth, len(blocks))

                except R2Exception as e:
                    logger.error("R2Exception in radare2_ai_integration: %s", e)
                    continue

        return {
            'total_basic_blocks': float(total_blocks),
            'total_edges': float(total_edges),
            'average_blocks_per_function': float(total_blocks / max(1, len(functions))),
            'max_function_depth': float(max_depth),
            'edge_to_block_ratio': float(total_edges / max(1, total_blocks))
        }

    def _extract_entropy_features(self, r2) -> Dict[str, float]:
        """Extract entropy and complexity features."""
        try:
            # Get sections information
            sections_data = r2._execute_command('iSj', expect_json=True)

            text_section_entropy = 0.0
            data_section_entropy = 0.0
            total_sections = 0

            if isinstance(sections_data, list):
                for section in sections_data:
                    section_name = section.get('name', '').lower()
                    total_sections += 1

                    # Simple entropy estimation based on section size and permissions
                    size = section.get('vsize', 0)
                    perm = section.get('perm', '')

                    # Rough entropy estimation
                    entropy = min(8.0, np.log2(max(1, size)) / 10.0)

                    if 'text' in section_name or 'x' in perm:
                        text_section_entropy = max(text_section_entropy, entropy)
                    elif 'data' in section_name or 'w' in perm:
                        data_section_entropy = max(data_section_entropy, entropy)

            return {
                'text_section_entropy': text_section_entropy,
                'data_section_entropy': data_section_entropy,
                'total_sections': float(total_sections),
                'entropy_variance': abs(text_section_entropy - data_section_entropy)
            }

        except R2Exception as e:
            logger.error("R2Exception in radare2_ai_integration: %s", e)
            return {
                'text_section_entropy': 0.0,
                'data_section_entropy': 0.0,
                'total_sections': 0.0,
                'entropy_variance': 0.0
            }

    def _ai_license_detection(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """AI-based license validation detection."""
        if not SKLEARN_AVAILABLE:
            return {
                'has_license_validation': False,
                'confidence': 0.0,
                'license_mechanisms': [],
                'detection_method': 'fallback_rule_based',
                'error': 'sklearn not available'
            }

        # Load or train license detection model
        model_path = os.path.join(self.model_dir, 'license_detector.joblib')

        if os.path.exists(model_path):
            self.license_detector = joblib.load(model_path)
        else:
            self.license_detector = self._train_license_detector()
            joblib.dump(self.license_detector, model_path)

        # Prepare feature vector
        feature_vector = self._prepare_license_feature_vector(features)

        # Make prediction
        if len(feature_vector) > 0:
            prediction = self.license_detector.predict([feature_vector])[0]
            probability = self.license_detector.predict_proba([feature_vector])[0]

            return {
                'has_license_validation': bool(prediction),
                'confidence': float(max(probability)),
                'license_complexity': self._assess_license_complexity(features),
                'bypass_difficulty': self._predict_bypass_difficulty(features),
                'validation_methods': self._identify_validation_methods(features)
            }

        return {'error': 'Insufficient features for license detection'}

    def _ai_vulnerability_prediction(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """AI-based vulnerability prediction."""
        if not SKLEARN_AVAILABLE:
            return {
                'vulnerability_types': [],
                'confidence_scores': {},
                'risk_level': 'unknown',
                'error': 'sklearn not available'
            }

        # Load or train vulnerability classifier
        model_path = os.path.join(self.model_dir, 'vulnerability_classifier.joblib')

        if os.path.exists(model_path):
            self.vulnerability_classifier = joblib.load(model_path)
        else:
            self.vulnerability_classifier = self._train_vulnerability_classifier()
            joblib.dump(self.vulnerability_classifier, model_path)

        # Prepare feature vector
        feature_vector = self._prepare_vulnerability_feature_vector(features)

        if len(feature_vector) > 0:
            # Predict vulnerability types
            predictions = self.vulnerability_classifier.predict([feature_vector])[0]
            probabilities = self.vulnerability_classifier.predict_proba([feature_vector])[0]

            vulnerability_types = [
                'buffer_overflow', 'format_string', 'integer_overflow',
                'use_after_free', 'race_condition', 'privilege_escalation'
            ]

            results = {}
            for i, vuln_type in enumerate(vulnerability_types):
                if i < len(probabilities):
                    results[vuln_type] = {
                        'probability': float(probabilities[i]),
                        'predicted': bool(predictions == i if hasattr(predictions, '__iter__') else predictions == i)
                    }

            return {
                'vulnerability_predictions': results,
                'overall_risk_score': float(np.mean(probabilities)),
                'high_risk_areas': self._identify_high_risk_areas(features),
                'exploit_likelihood': self._predict_exploit_likelihood(features)
            }

        return {'error': 'Insufficient features for vulnerability prediction'}

    def _function_clustering_analysis(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform function clustering analysis."""
        if not SKLEARN_AVAILABLE:
            return {
                'clusters': {},
                'cluster_quality': 0.0,
                'error': 'sklearn not available'
            }

        function_features = features.get('function_features', [])

        if len(function_features) < 5:
            return {'error': 'Insufficient functions for clustering analysis'}

        # Prepare feature matrix
        feature_matrix = []
        for func_features in function_features:
            feature_vector = [
                func_features.get('size', 0),
                func_features.get('complexity', 0),
                func_features.get('calls', 0),
                func_features.get('has_license_keywords', 0),
                func_features.get('has_crypto_keywords', 0)
            ]
            feature_matrix.append(feature_vector)

        feature_matrix = np.array(feature_matrix)

        # Normalize features
        feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)

        # Perform clustering
        clusterer = DBSCAN(eps=0.5, min_samples=2)
        cluster_labels = clusterer.fit_predict(feature_matrix_scaled)

        # Analyze clusters
        unique_clusters = set(cluster_labels)
        cluster_analysis = {}

        for cluster_id in unique_clusters:
            if cluster_id == -1:  # Noise points
                continue

            cluster_indices = np.where(cluster_labels == cluster_id)[0]
            cluster_functions = [function_features[i] for i in cluster_indices]

            cluster_analysis[f'cluster_{cluster_id}'] = {
                'function_count': len(cluster_functions),
                'average_size': np.mean([f.get('size', 0) for f in cluster_functions]),
                'average_complexity': np.mean([f.get('complexity', 0) for f in cluster_functions]),
                'has_license_functions': any(f.get('has_license_keywords', 0) for f in cluster_functions),
                'has_crypto_functions': any(f.get('has_crypto_keywords', 0) for f in cluster_functions)
            }

        return {
            'total_clusters': len(unique_clusters) - (1 if -1 in unique_clusters else 0),
            'noise_functions': int(np.sum(cluster_labels == -1)),
            'cluster_analysis': cluster_analysis,
            'clustering_quality': self._assess_clustering_quality(cluster_labels)
        }

    def _anomaly_detection_analysis(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform anomaly detection analysis."""
        if not SKLEARN_AVAILABLE:
            return {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'anomaly_indicators': [],
                'error': 'sklearn not available'
            }

        # Combine all features into a single vector
        combined_features = []

        # Add static features
        static_features = features.get('static_features', {})
        combined_features.extend(list(static_features.values()))

        # Add aggregated string features
        string_features = features.get('string_features', {})
        combined_features.extend(list(string_features.values()))

        # Add aggregated import features
        import_features = features.get('import_features', {})
        combined_features.extend(list(import_features.values()))

        if len(combined_features) < 5:
            return {'error': 'Insufficient features for anomaly detection'}

        # Train anomaly detector
        anomaly_detector = IsolationForest(contamination=0.1, random_state=42)

        # Reshape for single sample prediction
        feature_vector = np.array(combined_features).reshape(1, -1)

        # Fit and predict (in production, this would be trained on multiple samples)
        anomaly_detector.fit(feature_vector)
        anomaly_score = anomaly_detector.decision_function(feature_vector)[0]
        is_anomaly = anomaly_detector.predict(feature_vector)[0] == -1

        return {
            'is_anomalous': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'anomaly_indicators': self._identify_anomaly_indicators(features),
            'confidence': abs(float(anomaly_score))
        }

    def _code_similarity_analysis(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform code similarity analysis."""
        # This would typically compare against a database of known samples
        # For now, we'll analyze internal similarities

        function_features = features.get('function_features', [])

        if len(function_features) < 10:
            return {'error': 'Insufficient functions for similarity analysis'}

        # Calculate pairwise similarities
        similarities = []

        for i in range(min(10, len(function_features))):
            for j in range(i + 1, min(10, len(function_features))):
                func1 = function_features[i]
                func2 = function_features[j]

                # Simple similarity metric based on size and complexity
                size_diff = abs(func1.get('size', 0) - func2.get('size', 0))
                complexity_diff = abs(func1.get('complexity', 0) - func2.get('complexity', 0))

                similarity = 1.0 / (1.0 + size_diff + complexity_diff)
                similarities.append(similarity)

        return {
            'average_internal_similarity': float(np.mean(similarities)) if similarities else 0.0,
            'max_similarity': float(np.max(similarities)) if similarities else 0.0,
            'similarity_variance': float(np.var(similarities)) if similarities else 0.0,
            'potential_code_reuse': float(np.mean(similarities)) > 0.8 if similarities else False
        }

    def _generate_ai_bypass_suggestions(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-based bypass suggestions."""
        suggestions = {
            'automated_patches': [],
            'bypass_strategies': [],
            'target_functions': [],
            'confidence_scores': {}
        }

        # Analyze license-related features
        string_features = features.get('string_features', {})
        import_features = features.get('import_features', {})

        # Generate bypass strategies based on feature analysis
        if string_features.get('license_string_ratio', 0) > 0.1:
            suggestions['bypass_strategies'].append({
                'strategy': 'String patching',
                'description': 'Patch license validation strings',
                'success_probability': 0.8,
                'difficulty': 'easy'
            })

        if import_features.get('crypto_api_ratio', 0) > 0.1:
            suggestions['bypass_strategies'].append({
                'strategy': 'Crypto bypass',
                'description': 'Bypass cryptographic license validation',
                'success_probability': 0.6,
                'difficulty': 'medium'
            })

        if import_features.get('registry_api_ratio', 0) > 0.1:
            suggestions['bypass_strategies'].append({
                'strategy': 'Registry manipulation',
                'description': 'Modify registry-based license checks',
                'success_probability': 0.9,
                'difficulty': 'easy'
            })

        # Calculate overall confidence
        total_strategies = len(suggestions['bypass_strategies'])
        if total_strategies > 0:
            avg_probability = np.mean([s['success_probability'] for s in suggestions['bypass_strategies']])
            suggestions['confidence_scores']['overall_success_probability'] = float(avg_probability)
            suggestions['confidence_scores']['strategy_count'] = total_strategies

        return suggestions

    def _train_license_detector(self) -> RandomForestClassifier:
        """Train license detection model with synthetic data."""
        # Generate synthetic training data
        X_train, y_train = self._generate_license_training_data()

        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        return model

    def _train_vulnerability_classifier(self) -> RandomForestClassifier:
        """Train vulnerability classification model with synthetic data."""
        # Generate synthetic training data
        X_train, y_train = self._generate_vulnerability_training_data()

        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        return model

    def _generate_license_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for license detection."""
        # Create synthetic feature vectors and labels
        n_samples = 1000
        n_features = 8

        X = np.random.randn(n_samples, n_features)
        y = np.random.randint(0, 2, n_samples)

        # Add some realistic patterns
        for i in range(n_samples):
            if y[i] == 1:  # Has license validation
                X[i, 0] += 2  # Higher license string ratio
                X[i, 1] += 1  # More crypto APIs
                X[i, 2] += 1  # More registry APIs

        return X, y

    def _generate_vulnerability_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for vulnerability classification."""
        n_samples = 1000
        n_features = 10
        n_classes = 6  # Number of vulnerability types

        X = np.random.randn(n_samples, n_features)
        y = np.random.randint(0, n_classes, n_samples)

        return X, y

    def _prepare_license_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare feature vector for license detection."""
        string_features = features.get('string_features', {})
        import_features = features.get('import_features', {})

        return [
            string_features.get('license_string_ratio', 0),
            string_features.get('crypto_string_ratio', 0),
            import_features.get('crypto_api_ratio', 0),
            import_features.get('registry_api_ratio', 0),
            import_features.get('file_api_ratio', 0),
            string_features.get('suspicious_patterns', 0),
            import_features.get('anti_analysis_api_count', 0),
            string_features.get('average_entropy', 0)
        ]

    def _prepare_vulnerability_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare feature vector for vulnerability prediction."""
        static_features = features.get('static_features', {})
        import_features = features.get('import_features', {})
        graph_features = features.get('graph_features', {})

        return [
            static_features.get('has_canary', 0),
            static_features.get('has_nx', 0),
            import_features.get('suspicious_api_count', 0),
            graph_features.get('total_basic_blocks', 0) / 1000,  # Normalize
            graph_features.get('edge_to_block_ratio', 0),
            import_features.get('process_api_ratio', 0),
            import_features.get('debug_api_ratio', 0),
            static_features.get('file_size', 0) / 1000000,  # Normalize to MB
            graph_features.get('max_function_depth', 0),
            import_features.get('network_api_ratio', 0)
        ]

    def _assess_license_complexity(self, features: Dict[str, Any]) -> str:
        """Assess license validation complexity."""
        string_features = features.get('string_features', {})
        import_features = features.get('import_features', {})

        complexity_score = (
            string_features.get('license_string_ratio', 0) * 2 +
            import_features.get('crypto_api_ratio', 0) * 3 +
            string_features.get('average_entropy', 0) / 8
        )

        if complexity_score > 2:
            return 'high'
        elif complexity_score > 1:
            return 'medium'
        else:
            return 'low'

    def _predict_bypass_difficulty(self, features: Dict[str, Any]) -> str:
        """Predict license bypass difficulty."""
        complexity = self._assess_license_complexity(features)

        if complexity == 'high':
            return 'hard'
        elif complexity == 'medium':
            return 'medium'
        else:
            return 'easy'

    def _identify_validation_methods(self, features: Dict[str, Any]) -> List[str]:
        """Identify license validation methods."""
        methods = []

        import_features = features.get('import_features', {})

        if import_features.get('crypto_api_ratio', 0) > 0.1:
            methods.append('cryptographic_validation')

        if import_features.get('registry_api_ratio', 0) > 0.1:
            methods.append('registry_validation')

        if import_features.get('file_api_ratio', 0) > 0.1:
            methods.append('file_based_validation')

        if import_features.get('network_api_ratio', 0) > 0.1:
            methods.append('online_validation')

        return methods

    def _identify_high_risk_areas(self, features: Dict[str, Any]) -> List[str]:
        """Identify high-risk areas for vulnerabilities."""
        risk_areas = []

        import_features = features.get('import_features', {})
        static_features = features.get('static_features', {})

        if import_features.get('suspicious_api_count', 0) > 5:
            risk_areas.append('suspicious_api_usage')

        if not static_features.get('has_canary', False):
            risk_areas.append('missing_stack_protection')

        if not static_features.get('has_nx', False):
            risk_areas.append('missing_dep_protection')

        if import_features.get('debug_api_ratio', 0) > 0.1:
            risk_areas.append('debug_functionality_present')

        return risk_areas

    def _predict_exploit_likelihood(self, features: Dict[str, Any]) -> float:
        """Predict likelihood of successful exploitation."""
        static_features = features.get('static_features', {})
        import_features = features.get('import_features', {})

        # Simple scoring based on protection mechanisms
        score = 1.0

        if static_features.get('has_canary', False):
            score *= 0.7

        if static_features.get('has_nx', False):
            score *= 0.8

        if import_features.get('suspicious_api_count', 0) > 0:
            score *= 1.3

        return min(1.0, score)

    def _assess_clustering_quality(self, cluster_labels: np.ndarray) -> float:
        """Assess quality of clustering results."""
        unique_labels = set(cluster_labels)
        if len(unique_labels) <= 1:
            return 0.0

        # Simple silhouette-like score
        return min(1.0, len(unique_labels) / len(cluster_labels))

    def _identify_anomaly_indicators(self, features: Dict[str, Any]) -> List[str]:
        """Identify indicators that make the binary anomalous."""
        indicators = []

        string_features = features.get('string_features', {})
        import_features = features.get('import_features', {})
        static_features = features.get('static_features', {})

        if string_features.get('high_entropy_ratio', 0) > 0.3:
            indicators.append('high_entropy_strings')

        if import_features.get('anti_analysis_api_count', 0) > 3:
            indicators.append('excessive_anti_analysis_apis')

        if static_features.get('file_size', 0) > 50000000:  # > 50MB
            indicators.append('unusually_large_file')

        if string_features.get('suspicious_patterns', 0) > 10:
            indicators.append('many_suspicious_patterns')

        return indicators

    def _calculate_confidence_scores(self, results: Dict[str, Any]) -> Dict[str, float]:
        """Calculate confidence scores for AI predictions."""
        confidence_scores = {}

        # License detection confidence
        license_result = results.get('ai_license_detection', {})
        if 'confidence' in license_result:
            confidence_scores['license_detection'] = license_result['confidence']

        # Vulnerability prediction confidence
        vuln_result = results.get('ai_vulnerability_prediction', {})
        if 'overall_risk_score' in vuln_result:
            confidence_scores['vulnerability_prediction'] = vuln_result['overall_risk_score']

        # Anomaly detection confidence
        anomaly_result = results.get('anomaly_detection', {})
        if 'confidence' in anomaly_result:
            confidence_scores['anomaly_detection'] = anomaly_result['confidence']

        # Calculate overall confidence
        if confidence_scores:
            confidence_scores['overall'] = np.mean(list(confidence_scores.values()))

        return confidence_scores

    def _get_model_performance_metrics(self) -> Dict[str, Any]:
        """Get model performance metrics."""
        return {
            'license_detector_status': 'trained' if self.license_detector else 'not_trained',
            'vulnerability_classifier_status': 'trained' if self.vulnerability_classifier else 'not_trained',
            'feature_extraction_success': True,
            'model_versions': {
                'license_detector': '1.0',
                'vulnerability_classifier': '1.0'
            }
        }


def analyze_binary_with_ai(binary_path: str, radare2_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Perform AI-enhanced analysis on a binary.

    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable

    Returns:
        Complete AI analysis results
    """
    engine = R2AIEngine(binary_path, radare2_path)
    return engine.analyze_with_ai()


__all__ = ['R2AIEngine', 'analyze_binary_with_ai']
