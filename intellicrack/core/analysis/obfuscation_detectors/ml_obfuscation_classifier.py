"""
Machine Learning-Based Obfuscation Classification Engine

Advanced ML classifier for obfuscation pattern recognition using:
- Feature extraction from binary characteristics
- Multiple classification models (Random Forest, SVM, Neural Networks)
- Similarity analysis and clustering
- Automated signature generation
- Ensemble learning for improved accuracy

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import logging
import pickle
import numpy as np
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ....utils.logger import get_logger

logger = get_logger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.svm import SVC
    from sklearn.neural_network import MLPClassifier
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.decomposition import PCA
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


@dataclass
class ObfuscationFeatures:
    """Extracted features for ML classification"""
    # Control flow features
    cfg_complexity: float
    cyclomatic_complexity: int
    basic_block_count: int
    jump_instruction_ratio: float
    conditional_jump_ratio: float
    indirect_jump_count: int
    
    # String features
    string_entropy: float
    encrypted_string_ratio: float
    xor_pattern_count: int
    base64_pattern_count: int
    
    # API features
    dynamic_api_ratio: float
    api_hash_count: int
    indirect_call_ratio: float
    import_table_entropy: float
    
    # Code features
    instruction_entropy: float
    nop_instruction_ratio: float
    dead_code_ratio: float
    polymorphic_pattern_count: int
    
    # VM features
    vm_pattern_count: int
    bytecode_section_count: int
    handler_function_count: int
    
    # Statistical features
    file_entropy: float
    section_count: int
    packed_section_ratio: float
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numpy vector for ML"""
        return np.array([
            self.cfg_complexity,
            self.cyclomatic_complexity,
            self.basic_block_count,
            self.jump_instruction_ratio,
            self.conditional_jump_ratio,
            self.indirect_jump_count,
            self.string_entropy,
            self.encrypted_string_ratio,
            self.xor_pattern_count,
            self.base64_pattern_count,
            self.dynamic_api_ratio,
            self.api_hash_count,
            self.indirect_call_ratio,
            self.import_table_entropy,
            self.instruction_entropy,
            self.nop_instruction_ratio,
            self.dead_code_ratio,
            self.polymorphic_pattern_count,
            self.vm_pattern_count,
            self.bytecode_section_count,
            self.handler_function_count,
            self.file_entropy,
            self.section_count,
            self.packed_section_ratio
        ])
    
    @classmethod
    def get_feature_names(cls) -> List[str]:
        """Get feature names for ML models"""
        return [
            'cfg_complexity', 'cyclomatic_complexity', 'basic_block_count',
            'jump_instruction_ratio', 'conditional_jump_ratio', 'indirect_jump_count',
            'string_entropy', 'encrypted_string_ratio', 'xor_pattern_count',
            'base64_pattern_count', 'dynamic_api_ratio', 'api_hash_count',
            'indirect_call_ratio', 'import_table_entropy', 'instruction_entropy',
            'nop_instruction_ratio', 'dead_code_ratio', 'polymorphic_pattern_count',
            'vm_pattern_count', 'bytecode_section_count', 'handler_function_count',
            'file_entropy', 'section_count', 'packed_section_ratio'
        ]


@dataclass
class ClassificationResult:
    """ML classification result"""
    obfuscation_type: str
    confidence: float
    probability_scores: Dict[str, float]
    anomaly_score: float
    cluster_id: int
    feature_importance: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'obfuscation_type': self.obfuscation_type,
            'confidence': self.confidence,
            'probability_scores': self.probability_scores,
            'anomaly_score': self.anomaly_score,
            'cluster_id': self.cluster_id,
            'feature_importance': self.feature_importance
        }


@dataclass
class SimilarityResult:
    """Similarity analysis result"""
    similar_samples: List[Dict[str, Any]]
    similarity_scores: List[float]
    cluster_members: List[str]
    prototype_sample: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'similar_samples': self.similar_samples,
            'similarity_scores': self.similarity_scores,
            'cluster_members': self.cluster_members,
            'prototype_sample': self.prototype_sample
        }


class MLObfuscationClassifier:
    """Machine learning-based obfuscation classifier"""
    
    def __init__(self, r2_session: Optional[Any] = None, model_dir: Optional[str] = None):
        """Initialize ML obfuscation classifier
        
        Args:
            r2_session: Optional radare2 session
            model_dir: Directory to store/load trained models
        """
        self.r2 = r2_session
        self.logger = logger
        
        if not SKLEARN_AVAILABLE:
            self.logger.warning("scikit-learn not available, ML features disabled")
            self.enabled = False
            return
        
        self.enabled = True
        self.model_dir = Path(model_dir) if model_dir else Path.cwd() / "models"
        self.model_dir.mkdir(exist_ok=True)
        
        # Initialize models
        self.models = self._initialize_models()
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=15)  # Dimensionality reduction
        
        # Clustering models
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.kmeans = KMeans(n_clusters=8, random_state=42)
        
        # Anomaly detection
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        
        # Training data storage
        self.training_features: List[np.ndarray] = []
        self.training_labels: List[str] = []
        self.feature_cache: Dict[str, ObfuscationFeatures] = {}
        
        # Load existing models if available
        self._load_models()
    
    def extract_features(self, file_path: Optional[str] = None) -> Optional[ObfuscationFeatures]:
        """Extract ML features from binary
        
        Args:
            file_path: Optional file path for caching
            
        Returns:
            Extracted features or None if extraction failed
        """
        if not self.enabled or not self.r2:
            return None
        
        # Check cache first
        if file_path and file_path in self.feature_cache:
            return self.feature_cache[file_path]
        
        try:
            features = self._extract_comprehensive_features()
            
            # Cache features if file path provided
            if file_path and features:
                self.feature_cache[file_path] = features
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return None
    
    def classify_obfuscation(self, features: ObfuscationFeatures) -> Optional[ClassificationResult]:
        """Classify obfuscation type using ML models
        
        Args:
            features: Extracted features
            
        Returns:
            Classification result or None if classification failed
        """
        if not self.enabled or not features:
            return None
        
        try:
            feature_vector = features.to_vector().reshape(1, -1)
            
            # Scale features
            if hasattr(self.scaler, 'scale_'):
                scaled_features = self.scaler.transform(feature_vector)
            else:
                scaled_features = feature_vector
            
            # Get predictions from all models
            predictions = {}
            probabilities = {}
            
            for model_name, model in self.models.items():
                if hasattr(model, 'predict') and model is not None:
                    try:
                        pred = model.predict(scaled_features)[0]
                        predictions[model_name] = pred
                        
                        if hasattr(model, 'predict_proba'):
                            proba = model.predict_proba(scaled_features)[0]
                            probabilities[model_name] = proba
                    except Exception as e:
                        self.logger.warning(f"Model {model_name} prediction failed: {e}")
            
            if not predictions:
                return None
            
            # Ensemble prediction (majority vote)
            final_prediction = self._ensemble_predict(predictions, probabilities)
            
            # Calculate anomaly score
            anomaly_score = self._calculate_anomaly_score(scaled_features)
            
            # Get cluster assignment
            cluster_id = self._get_cluster_assignment(scaled_features)
            
            # Calculate feature importance
            feature_importance = self._calculate_feature_importance(scaled_features, features)
            
            return ClassificationResult(
                obfuscation_type=final_prediction['type'],
                confidence=final_prediction['confidence'],
                probability_scores=final_prediction['probabilities'],
                anomaly_score=anomaly_score,
                cluster_id=cluster_id,
                feature_importance=feature_importance
            )
            
        except Exception as e:
            self.logger.error(f"Obfuscation classification failed: {e}")
            return None
    
    def analyze_similarity(self, features: ObfuscationFeatures, 
                         sample_database: Optional[List[Dict]] = None) -> Optional[SimilarityResult]:
        """Analyze similarity with known samples
        
        Args:
            features: Features to analyze
            sample_database: Optional database of known samples
            
        Returns:
            Similarity analysis result
        """
        if not self.enabled or not features:
            return None
        
        try:
            feature_vector = features.to_vector()
            
            # Find similar samples in training data
            similar_samples = self._find_similar_samples(feature_vector)
            
            # Get cluster members
            cluster_members = self._get_cluster_members(feature_vector)
            
            # Find prototype sample
            prototype = self._find_prototype_sample(feature_vector, cluster_members)
            
            return SimilarityResult(
                similar_samples=similar_samples,
                similarity_scores=[s['similarity'] for s in similar_samples],
                cluster_members=cluster_members,
                prototype_sample=prototype
            )
            
        except Exception as e:
            self.logger.error(f"Similarity analysis failed: {e}")
            return None
    
    def generate_signature(self, features: ObfuscationFeatures, 
                         obfuscation_type: str) -> Optional[Dict[str, Any]]:
        """Generate automated signature from features
        
        Args:
            features: Features to generate signature from
            obfuscation_type: Type of obfuscation
            
        Returns:
            Generated signature or None if generation failed
        """
        if not self.enabled or not features:
            return None
        
        try:
            # Extract key distinguishing features
            feature_vector = features.to_vector()
            feature_names = ObfuscationFeatures.get_feature_names()
            
            # Find most important features for this obfuscation type
            important_features = self._find_signature_features(feature_vector, obfuscation_type)
            
            # Generate signature rules
            signature_rules = []
            for feature_idx, importance in important_features:
                feature_name = feature_names[feature_idx]
                feature_value = feature_vector[feature_idx]
                
                rule = {
                    'feature': feature_name,
                    'threshold': feature_value,
                    'importance': importance,
                    'condition': self._generate_condition(feature_name, feature_value)
                }
                signature_rules.append(rule)
            
            signature = {
                'type': obfuscation_type,
                'rules': signature_rules,
                'confidence_threshold': 0.7,
                'generated_timestamp': self._get_timestamp(),
                'feature_hash': hashlib.sha256(feature_vector.tobytes()).hexdigest()[:16]
            }
            
            return signature
            
        except Exception as e:
            self.logger.error(f"Signature generation failed: {e}")
            return None
    
    def train_models(self, training_data: List[Tuple[ObfuscationFeatures, str]]) -> bool:
        """Train ML models with provided data
        
        Args:
            training_data: List of (features, label) tuples
            
        Returns:
            True if training succeeded, False otherwise
        """
        if not self.enabled or not training_data:
            return False
        
        try:
            # Prepare training data
            X = np.array([features.to_vector() for features, _ in training_data])
            y = np.array([label for _, label in training_data])
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Apply PCA
            X_pca = self.pca.fit_transform(X_scaled)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_pca, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Train models
            training_results = {}
            for model_name, model in self.models.items():
                try:
                    self.logger.info(f"Training {model_name}...")
                    model.fit(X_train, y_train)
                    
                    # Evaluate
                    train_score = model.score(X_train, y_train)
                    test_score = model.score(X_test, y_test)
                    
                    training_results[model_name] = {
                        'train_score': train_score,
                        'test_score': test_score
                    }
                    
                    self.logger.info(f"{model_name} - Train: {train_score:.3f}, Test: {test_score:.3f}")
                    
                except Exception as e:
                    self.logger.error(f"Training {model_name} failed: {e}")
            
            # Train clustering models
            self.dbscan.fit(X_scaled)
            self.kmeans.fit(X_scaled)
            
            # Train anomaly detection
            self.isolation_forest.fit(X_scaled)
            
            # Store training data
            self.training_features = [f.to_vector() for f, _ in training_data]
            self.training_labels = [label for _, label in training_data]
            
            # Save models
            self._save_models()
            
            self.logger.info(f"Model training completed. Results: {training_results}")
            return True
            
        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            return False
    
    def _initialize_models(self) -> Dict[str, Any]:
        """Initialize ML models"""
        if not SKLEARN_AVAILABLE:
            return {}
        
        models = {
            'random_forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'svm': SVC(
                kernel='rbf',
                probability=True,
                random_state=42
            ),
            'neural_network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                max_iter=1000,
                random_state=42
            )
        }
        
        return models
    
    def _extract_comprehensive_features(self) -> Optional[ObfuscationFeatures]:
        """Extract comprehensive features from current binary"""
        if not self.r2:
            return None
        
        try:
            # Control flow features
            cfg_complexity = self._calculate_cfg_complexity()
            cyclomatic_complexity = self._calculate_cyclomatic_complexity()
            basic_block_count = self._count_basic_blocks()
            jump_instruction_ratio = self._calculate_jump_instruction_ratio()
            conditional_jump_ratio = self._calculate_conditional_jump_ratio()
            indirect_jump_count = self._count_indirect_jumps()
            
            # String features
            string_entropy = self._calculate_string_entropy()
            encrypted_string_ratio = self._calculate_encrypted_string_ratio()
            xor_pattern_count = self._count_xor_patterns()
            base64_pattern_count = self._count_base64_patterns()
            
            # API features
            dynamic_api_ratio = self._calculate_dynamic_api_ratio()
            api_hash_count = self._count_api_hashes()
            indirect_call_ratio = self._calculate_indirect_call_ratio()
            import_table_entropy = self._calculate_import_table_entropy()
            
            # Code features
            instruction_entropy = self._calculate_instruction_entropy()
            nop_instruction_ratio = self._calculate_nop_instruction_ratio()
            dead_code_ratio = self._calculate_dead_code_ratio()
            polymorphic_pattern_count = self._count_polymorphic_patterns()
            
            # VM features
            vm_pattern_count = self._count_vm_patterns()
            bytecode_section_count = self._count_bytecode_sections()
            handler_function_count = self._count_handler_functions()
            
            # Statistical features
            file_entropy = self._calculate_file_entropy()
            section_count = self._count_sections()
            packed_section_ratio = self._calculate_packed_section_ratio()
            
            return ObfuscationFeatures(
                cfg_complexity=cfg_complexity,
                cyclomatic_complexity=cyclomatic_complexity,
                basic_block_count=basic_block_count,
                jump_instruction_ratio=jump_instruction_ratio,
                conditional_jump_ratio=conditional_jump_ratio,
                indirect_jump_count=indirect_jump_count,
                string_entropy=string_entropy,
                encrypted_string_ratio=encrypted_string_ratio,
                xor_pattern_count=xor_pattern_count,
                base64_pattern_count=base64_pattern_count,
                dynamic_api_ratio=dynamic_api_ratio,
                api_hash_count=api_hash_count,
                indirect_call_ratio=indirect_call_ratio,
                import_table_entropy=import_table_entropy,
                instruction_entropy=instruction_entropy,
                nop_instruction_ratio=nop_instruction_ratio,
                dead_code_ratio=dead_code_ratio,
                polymorphic_pattern_count=polymorphic_pattern_count,
                vm_pattern_count=vm_pattern_count,
                bytecode_section_count=bytecode_section_count,
                handler_function_count=handler_function_count,
                file_entropy=file_entropy,
                section_count=section_count,
                packed_section_ratio=packed_section_ratio
            )
            
        except Exception as e:
            self.logger.error(f"Comprehensive feature extraction failed: {e}")
            return None
    
    def _ensemble_predict(self, predictions: Dict[str, str], 
                         probabilities: Dict[str, np.ndarray]) -> Dict[str, Any]:
        """Combine predictions from multiple models"""
        if not predictions:
            return {'type': 'unknown', 'confidence': 0.0, 'probabilities': {}}
        
        # Simple majority vote
        prediction_counts = {}
        for pred in predictions.values():
            prediction_counts[pred] = prediction_counts.get(pred, 0) + 1
        
        # Get most common prediction
        final_prediction = max(prediction_counts, key=prediction_counts.get)
        confidence = prediction_counts[final_prediction] / len(predictions)
        
        # Average probabilities if available
        avg_probabilities = {}
        if probabilities:
            all_classes = set()
            for proba_array in probabilities.values():
                all_classes.update(range(len(proba_array)))
            
            for class_idx in all_classes:
                class_probas = []
                for proba_array in probabilities.values():
                    if class_idx < len(proba_array):
                        class_probas.append(proba_array[class_idx])
                
                if class_probas:
                    avg_probabilities[f'class_{class_idx}'] = np.mean(class_probas)
        
        return {
            'type': final_prediction,
            'confidence': confidence,
            'probabilities': avg_probabilities
        }
    
    def _calculate_anomaly_score(self, features: np.ndarray) -> float:
        """Calculate anomaly score for features"""
        try:
            if hasattr(self.isolation_forest, 'decision_function'):
                score = self.isolation_forest.decision_function(features)[0]
                # Normalize to 0-1 range (lower = more anomalous)
                return max(0.0, min(1.0, (score + 0.5) / 1.0))
            return 0.5
        except Exception:
            return 0.5
    
    def _get_cluster_assignment(self, features: np.ndarray) -> int:
        """Get cluster assignment for features"""
        try:
            if hasattr(self.kmeans, 'predict'):
                return int(self.kmeans.predict(features)[0])
            return -1
        except Exception:
            return -1
    
    def _calculate_feature_importance(self, features: np.ndarray, 
                                    feature_obj: ObfuscationFeatures) -> Dict[str, float]:
        """Calculate feature importance scores"""
        try:
            # Use Random Forest feature importance if available
            if 'random_forest' in self.models and hasattr(self.models['random_forest'], 'feature_importances_'):
                importances = self.models['random_forest'].feature_importances_
                feature_names = ObfuscationFeatures.get_feature_names()
                
                # Only use features that exist in the PCA-transformed space
                if len(importances) <= len(feature_names):
                    return dict(zip(feature_names[:len(importances)], importances))
            
            # Fallback: simple variance-based importance
            feature_vector = feature_obj.to_vector()
            max_val = np.max(np.abs(feature_vector))
            if max_val > 0:
                normalized_features = feature_vector / max_val
                return dict(zip(ObfuscationFeatures.get_feature_names(), normalized_features))
            
            return {}
            
        except Exception as e:
            self.logger.warning(f"Feature importance calculation failed: {e}")
            return {}
    
    def _find_similar_samples(self, feature_vector: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """Find similar samples in training data"""
        similar_samples = []
        
        if not self.training_features:
            return similar_samples
        
        try:
            # Calculate similarities with training samples
            similarities = []
            for i, train_features in enumerate(self.training_features):
                # Cosine similarity
                similarity = np.dot(feature_vector, train_features) / (
                    np.linalg.norm(feature_vector) * np.linalg.norm(train_features)
                )
                similarities.append((i, similarity))
            
            # Sort by similarity and get top k
            similarities.sort(key=lambda x: x[1], reverse=True)
            
            for i, similarity in similarities[:top_k]:
                similar_samples.append({
                    'index': i,
                    'similarity': float(similarity),
                    'label': self.training_labels[i] if i < len(self.training_labels) else 'unknown'
                })
            
            return similar_samples
            
        except Exception as e:
            self.logger.warning(f"Similar sample search failed: {e}")
            return []
    
    def _get_cluster_members(self, feature_vector: np.ndarray) -> List[str]:
        """Get members of the same cluster"""
        try:
            cluster_id = self._get_cluster_assignment(feature_vector.reshape(1, -1))
            
            if cluster_id == -1 or not self.training_features:
                return []
            
            # Find other samples in the same cluster
            cluster_members = []
            for i, train_features in enumerate(self.training_features):
                train_cluster = self._get_cluster_assignment(train_features.reshape(1, -1))
                if train_cluster == cluster_id and i < len(self.training_labels):
                    cluster_members.append(self.training_labels[i])
            
            return cluster_members
            
        except Exception as e:
            self.logger.warning(f"Cluster member search failed: {e}")
            return []
    
    def _find_prototype_sample(self, feature_vector: np.ndarray, 
                             cluster_members: List[str]) -> Optional[str]:
        """Find prototype sample for the cluster"""
        if not cluster_members:
            return None
        
        # For now, return the most common label in the cluster
        if cluster_members:
            from collections import Counter
            counter = Counter(cluster_members)
            return counter.most_common(1)[0][0]
        
        return None
    
    def _find_signature_features(self, feature_vector: np.ndarray, 
                               obfuscation_type: str, top_k: int = 5) -> List[Tuple[int, float]]:
        """Find most important features for signature generation"""
        feature_importance = []
        
        try:
            # Use feature importance from trained models if available
            if 'random_forest' in self.models and hasattr(self.models['random_forest'], 'feature_importances_'):
                importances = self.models['random_forest'].feature_importances_
                
                # Get top k most important features
                feature_indices = np.argsort(importances)[-top_k:][::-1]
                
                for idx in feature_indices:
                    if idx < len(importances):
                        feature_importance.append((int(idx), float(importances[idx])))
            
            else:
                # Fallback: use feature magnitude
                magnitudes = np.abs(feature_vector)
                top_indices = np.argsort(magnitudes)[-top_k:][::-1]
                
                for idx in top_indices:
                    feature_importance.append((int(idx), float(magnitudes[idx])))
            
            return feature_importance
            
        except Exception as e:
            self.logger.warning(f"Signature feature finding failed: {e}")
            return []
    
    def _generate_condition(self, feature_name: str, feature_value: float) -> str:
        """Generate condition string for signature rule"""
        # Simple threshold-based conditions
        if 'ratio' in feature_name or 'entropy' in feature_name:
            return f"{feature_name} > {feature_value * 0.8:.3f}"
        elif 'count' in feature_name:
            return f"{feature_name} >= {max(1, int(feature_value * 0.5))}"
        else:
            return f"{feature_name} > {feature_value * 0.7:.3f}"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp string"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _save_models(self) -> None:
        """Save trained models to disk"""
        try:
            model_files = {
                'scaler': self.scaler,
                'pca': self.pca,
                'dbscan': self.dbscan,
                'kmeans': self.kmeans,
                'isolation_forest': self.isolation_forest
            }
            
            # Save sklearn models
            for name, model in model_files.items():
                if model is not None:
                    model_path = self.model_dir / f"{name}.pkl"
                    with open(model_path, 'wb') as f:
                        pickle.dump(model, f)
            
            # Save main classifiers
            for name, model in self.models.items():
                if model is not None:
                    model_path = self.model_dir / f"{name}.pkl"
                    with open(model_path, 'wb') as f:
                        pickle.dump(model, f)
            
            # Save training data
            training_data = {
                'features': self.training_features,
                'labels': self.training_labels
            }
            training_path = self.model_dir / "training_data.pkl"
            with open(training_path, 'wb') as f:
                pickle.dump(training_data, f)
            
            self.logger.info(f"Models saved to {self.model_dir}")
            
        except Exception as e:
            self.logger.error(f"Model saving failed: {e}")
    
    def _load_models(self) -> None:
        """Load trained models from disk"""
        try:
            # Load sklearn models
            model_files = ['scaler', 'pca', 'dbscan', 'kmeans', 'isolation_forest']
            
            for name in model_files:
                model_path = self.model_dir / f"{name}.pkl"
                if model_path.exists():
                    with open(model_path, 'rb') as f:
                        setattr(self, name, pickle.load(f))
            
            # Load main classifiers
            for name in self.models.keys():
                model_path = self.model_dir / f"{name}.pkl"
                if model_path.exists():
                    with open(model_path, 'rb') as f:
                        self.models[name] = pickle.load(f)
            
            # Load training data
            training_path = self.model_dir / "training_data.pkl"
            if training_path.exists():
                with open(training_path, 'rb') as f:
                    training_data = pickle.load(f)
                    self.training_features = training_data.get('features', [])
                    self.training_labels = training_data.get('labels', [])
            
            self.logger.info(f"Models loaded from {self.model_dir}")
            
        except Exception as e:
            self.logger.warning(f"Model loading failed: {e}")
    
    # Feature extraction helper methods
    
    def _calculate_cfg_complexity(self) -> float:
        """Calculate control flow graph complexity"""
        try:
            if not self.r2:
                return 0.0
            
            functions = self.r2.cmdj("aflj") or []
            if not functions:
                return 0.0
            
            total_complexity = 0.0
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Get basic blocks for function
                bbs = self.r2.cmdj(f"afbj @ {func_addr}") or []
                
                # Calculate edges and complexity
                edge_count = 0
                for bb in bbs:
                    jump = bb.get('jump', 0)
                    fail = bb.get('fail', 0)
                    if jump > 0:
                        edge_count += 1
                    if fail > 0:
                        edge_count += 1
                
                # Cyclomatic complexity = edges - nodes + 2
                if len(bbs) > 0:
                    complexity = max(1, edge_count - len(bbs) + 2)
                    total_complexity += complexity
            
            return total_complexity / max(1, len(functions))
            
        except Exception as e:
            self.logger.warning(f"CFG complexity calculation failed: {e}")
            return 0.0    
    def _calculate_cyclomatic_complexity(self) -> int:
        """Calculate cyclomatic complexity"""
        try:
            if not self.r2:
                return 0
            
            functions = self.r2.cmdj("aflj") or []
            total_complexity = 0
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Get function disassembly
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Count decision points (conditional jumps)
                decision_points = len([line for line in disasm.split('\n') 
                                     if any(jmp in line.lower() for jmp in ['je ', 'jz ', 'jne ', 'jnz ', 'jl ', 'jg '])])
                
                # Cyclomatic complexity = decision points + 1
                total_complexity += decision_points + 1
            
            return total_complexity
            
        except Exception as e:
            self.logger.warning(f"Cyclomatic complexity calculation failed: {e}")
            return 0
    
    def _count_basic_blocks(self) -> int:
        """Count total basic blocks"""
        try:
            if not self.r2:
                return 0
            
            bb_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                bbs = self.r2.cmdj(f"afbj @ {func_addr}") or []
                bb_count += len(bbs)
            
            return bb_count
            
        except Exception as e:
            self.logger.warning(f"Basic block counting failed: {e}")
            return 0
    
    def _calculate_jump_instruction_ratio(self) -> float:
        """Calculate ratio of jump instructions"""
        try:
            if not self.r2:
                return 0.0
            
            total_instructions = 0
            jump_instructions = 0
            
            functions = self.r2.cmdj("aflj") or []
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                lines = disasm.split('\n')
                for line in lines:
                    if ';' in line and ('0x' in line):  # Valid instruction line
                        total_instructions += 1
                        if any(jmp in line.lower() for jmp in ['jmp', 'je', 'jne', 'jz', 'jnz', 'call']):
                            jump_instructions += 1
            
            return jump_instructions / max(1, total_instructions)
            
        except Exception as e:
            self.logger.warning(f"Jump instruction ratio calculation failed: {e}")
            return 0.0
    
    def _calculate_conditional_jump_ratio(self) -> float:
        """Calculate ratio of conditional jump instructions"""
        try:
            if not self.r2:
                return 0.0
            
            total_jumps = 0
            conditional_jumps = 0
            
            functions = self.r2.cmdj("aflj") or []
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                for line in disasm.split('\n'):
                    if any(jmp in line.lower() for jmp in ['jmp', 'je', 'jne', 'jz', 'jnz', 'jl', 'jg']):
                        total_jumps += 1
                        if any(cond in line.lower() for cond in ['je', 'jne', 'jz', 'jnz', 'jl', 'jg']):
                            conditional_jumps += 1
            
            return conditional_jumps / max(1, total_jumps)
            
        except Exception as e:
            self.logger.warning(f"Conditional jump ratio calculation failed: {e}")
            return 0.0
    
    def _count_indirect_jumps(self) -> int:
        """Count indirect jump instructions"""
        try:
            if not self.r2:
                return 0
            
            indirect_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for indirect jumps (register or memory operands)
                for line in disasm.split('\n'):
                    if ('jmp' in line.lower() and 
                        ('[' in line or any(reg in line for reg in ['eax', 'ebx', 'ecx', 'edx']))):
                        indirect_count += 1
            
            return indirect_count
            
        except Exception as e:
            self.logger.warning(f"Indirect jump counting failed: {e}")
            return 0
    
    def _calculate_string_entropy(self) -> float:
        """Calculate entropy of strings in binary"""
        try:
            if not self.r2:
                return 0.0
            
            strings = self.r2.cmdj("izj") or []
            if not strings:
                return 0.0
            
            # Combine all strings
            all_text = ''.join([s.get('string', '') for s in strings])
            
            if not all_text:
                return 0.0
            
            # Calculate Shannon entropy
            from collections import Counter
            counts = Counter(all_text)
            total = len(all_text)
            
            entropy = 0.0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            
            return entropy
            
        except Exception as e:
            self.logger.warning(f"String entropy calculation failed: {e}")
            return 0.0
    
    def _calculate_encrypted_string_ratio(self) -> float:
        """Calculate ratio of potentially encrypted strings"""
        try:
            if not self.r2:
                return 0.0
            
            strings = self.r2.cmdj("izj") or []
            if not strings:
                return 0.0
            
            encrypted_count = 0
            for s in strings:
                string_val = s.get('string', '')
                
                # Check for high entropy (potential encryption)
                if len(string_val) > 10:
                    from collections import Counter
                    counts = Counter(string_val)
                    entropy = -sum(p * np.log2(p) for p in 
                                 (count/len(string_val) for count in counts.values()) if p > 0)
                    
                    if entropy > 4.0:  # High entropy threshold
                        encrypted_count += 1
            
            return encrypted_count / len(strings)
            
        except Exception as e:
            self.logger.warning(f"Encrypted string ratio calculation failed: {e}")
            return 0.0
    
    def _count_xor_patterns(self) -> int:
        """Count XOR encryption patterns"""
        try:
            if not self.r2:
                return 0
            
            xor_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Count XOR instructions
                xor_count += len([line for line in disasm.split('\n') 
                                if 'xor' in line.lower() and 'xor eax, eax' not in line.lower()])
            
            return xor_count
            
        except Exception as e:
            self.logger.warning(f"XOR pattern counting failed: {e}")
            return 0
    
    def _count_base64_patterns(self) -> int:
        """Count Base64 encoding patterns"""
        try:
            if not self.r2:
                return 0
            
            strings = self.r2.cmdj("izj") or []
            base64_count = 0
            
            import re
            base64_pattern = re.compile(r'^[A-Za-z0-9+/]{4,}={0,2}$')
            
            for s in strings:
                string_val = s.get('string', '')
                if len(string_val) > 20 and base64_pattern.match(string_val):
                    base64_count += 1
            
            return base64_count
            
        except Exception as e:
            self.logger.warning(f"Base64 pattern counting failed: {e}")
            return 0
    
    def _calculate_dynamic_api_ratio(self) -> float:
        """Calculate ratio of dynamic API loading"""
        try:
            if not self.r2:
                return 0.0
            
            imports = self.r2.cmdj("iij") or []
            if not imports:
                return 0.0
            
            dynamic_apis = ['LoadLibrary', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress']
            dynamic_count = 0
            
            for imp in imports:
                name = imp.get('name', '')
                if any(api in name for api in dynamic_apis):
                    dynamic_count += 1
            
            return dynamic_count / len(imports)
            
        except Exception as e:
            self.logger.warning(f"Dynamic API ratio calculation failed: {e}")
            return 0.0
    
    def _count_api_hashes(self) -> int:
        """Count potential API hash usage"""
        try:
            if not self.r2:
                return 0
            
            # Look for hash-like constants
            hash_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for large hex constants (potential hashes)
                import re
                hash_patterns = re.findall(r'0x[0-9a-fA-F]{8}', disasm)
                hash_count += len([h for h in hash_patterns if int(h, 16) > 0x10000000])
            
            return hash_count
            
        except Exception as e:
            self.logger.warning(f"API hash counting failed: {e}")
            return 0
    
    def _calculate_indirect_call_ratio(self) -> float:
        """Calculate ratio of indirect calls"""
        try:
            if not self.r2:
                return 0.0
            
            total_calls = 0
            indirect_calls = 0
            
            functions = self.r2.cmdj("aflj") or []
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                for line in disasm.split('\n'):
                    if 'call' in line.lower():
                        total_calls += 1
                        # Indirect call if it uses register or memory
                        if '[' in line or any(reg in line for reg in ['eax', 'ebx', 'ecx', 'edx']):
                            indirect_calls += 1
            
            return indirect_calls / max(1, total_calls)
            
        except Exception as e:
            self.logger.warning(f"Indirect call ratio calculation failed: {e}")
            return 0.0
    
    def _calculate_import_table_entropy(self) -> float:
        """Calculate entropy of import table"""
        try:
            if not self.r2:
                return 0.0
            
            imports = self.r2.cmdj("iij") or []
            if not imports:
                return 0.0
            
            # Get import names
            import_names = [imp.get('name', '') for imp in imports]
            import_text = ''.join(import_names)
            
            if not import_text:
                return 0.0
            
            # Calculate entropy
            from collections import Counter
            counts = Counter(import_text)
            total = len(import_text)
            
            entropy = 0.0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            
            return entropy
            
        except Exception as e:
            self.logger.warning(f"Import table entropy calculation failed: {e}")
            return 0.0
    
    def _calculate_instruction_entropy(self) -> float:
        """Calculate entropy of instruction opcodes"""
        try:
            if not self.r2:
                return 0.0
            
            opcodes = []
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                ops = self.r2.cmdj(f"pdfj @ {func_addr}") or []
                
                for op in ops:
                    if isinstance(op, dict):
                        opcode = op.get('opcode', '').split()[0]  # First word is the opcode
                        if opcode:
                            opcodes.append(opcode)
            
            if not opcodes:
                return 0.0
            
            # Calculate entropy
            from collections import Counter
            counts = Counter(opcodes)
            total = len(opcodes)
            
            entropy = 0.0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            
            return entropy
            
        except Exception as e:
            self.logger.warning(f"Instruction entropy calculation failed: {e}")
            return 0.0
    
    def _calculate_nop_instruction_ratio(self) -> float:
        """Calculate ratio of NOP instructions"""
        try:
            if not self.r2:
                return 0.0
            
            total_instructions = 0
            nop_instructions = 0
            
            functions = self.r2.cmdj("aflj") or []
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                for line in disasm.split('\n'):
                    if ';' in line and '0x' in line:  # Valid instruction
                        total_instructions += 1
                        if 'nop' in line.lower():
                            nop_instructions += 1
            
            return nop_instructions / max(1, total_instructions)
            
        except Exception as e:
            self.logger.warning(f"NOP instruction ratio calculation failed: {e}")
            return 0.0
    
    def _calculate_dead_code_ratio(self) -> float:
        """Calculate ratio of potentially dead code"""
        try:
            if not self.r2:
                return 0.0
            
            # Simple heuristic: unreferenced functions
            functions = self.r2.cmdj("aflj") or []
            if not functions:
                return 0.0
            
            referenced_functions = set()
            
            # Find all function calls
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Extract called addresses
                import re
                calls = re.findall(r'call\s+(?:0x)?([0-9a-fA-F]+)', disasm)
                for call in calls:
                    try:
                        referenced_functions.add(int(call, 16))
                    except ValueError:
                        pass
            
            # Count unreferenced functions
            unreferenced = 0
            for func in functions:
                func_addr = func.get('offset', 0)
                if func_addr not in referenced_functions:
                    unreferenced += 1
            
            return unreferenced / len(functions)
            
        except Exception as e:
            self.logger.warning(f"Dead code ratio calculation failed: {e}")
            return 0.0
    
    def _count_polymorphic_patterns(self) -> int:
        """Count polymorphic code patterns"""
        try:
            if not self.r2:
                return 0
            
            poly_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for instruction substitution patterns
                lines = disasm.split('\n')
                for i, line in enumerate(lines[:-1]):
                    next_line = lines[i + 1]
                    
                    # Check for equivalent instructions (polymorphism indicator)
                    if (('mov' in line and 'push' in next_line and 'pop' in lines[min(i+2, len(lines)-1)]) or
                        ('add' in line and 'sub' in next_line) or
                        ('xor' in line and 'mov' in next_line and ', 0' in next_line)):
                        poly_count += 1
            
            return poly_count
            
        except Exception as e:
            self.logger.warning(f"Polymorphic pattern counting failed: {e}")
            return 0
    
    def _count_vm_patterns(self) -> int:
        """Count virtualization patterns"""
        try:
            if not self.r2:
                return 0
            
            vm_count = 0
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                # Look for VM-like patterns
                vm_indicators = [
                    'switch', 'jump table', 'computed jump',
                    'pushad', 'popad', 'context',
                    'dispatch', 'handler'
                ]
                
                for indicator in vm_indicators:
                    if indicator in disasm.lower():
                        vm_count += 1
                        break  # Count each function only once
            
            return vm_count
            
        except Exception as e:
            self.logger.warning(f"VM pattern counting failed: {e}")
            return 0
    
    def _count_bytecode_sections(self) -> int:
        """Count potential bytecode sections"""
        try:
            if not self.r2:
                return 0
            
            sections = self.r2.cmdj("iSj") or []
            bytecode_count = 0
            
            for section in sections:
                name = section.get('name', '').lower()
                flags = section.get('flags', '').lower()
                size = section.get('vsize', 0)
                
                # Check for data sections that might contain bytecode
                if ('data' in flags and 100 < size < 100000 and 
                    not any(skip in name for skip in ['.text', '.rsrc', '.reloc'])):
                    bytecode_count += 1
            
            return bytecode_count
            
        except Exception as e:
            self.logger.warning(f"Bytecode section counting failed: {e}")
            return 0
    
    def _count_handler_functions(self) -> int:
        """Count potential handler functions"""
        try:
            if not self.r2:
                return 0
            
            functions = self.r2.cmdj("aflj") or []
            handler_count = 0
            
            # Look for small functions (typical of handlers)
            small_functions = [f for f in functions if f.get('size', 0) < 200]
            
            # If many small functions exist, likely handlers
            if len(small_functions) > 10:
                handler_count = len(small_functions)
            
            return handler_count
            
        except Exception as e:
            self.logger.warning(f"Handler function counting failed: {e}")
            return 0
    
    def _calculate_file_entropy(self) -> float:
        """Calculate overall file entropy"""
        try:
            if not self.r2:
                return 0.0
            
            # Get file size and calculate entropy over sections
            sections = self.r2.cmdj("iSj") or []
            if not sections:
                return 0.0
            
            total_entropy = 0.0
            total_size = 0
            
            for section in sections:
                size = section.get('vsize', 0)
                addr = section.get('vaddr', 0)
                
                if size > 0:
                    # Sample some data from the section
                    sample_size = min(size, 1024)
                    data = self.r2.cmd(f"p8 {sample_size} @ {addr}")
                    
                    if data:
                        try:
                            bytes_data = bytes.fromhex(data)
                            
                            # Calculate entropy
                            from collections import Counter
                            counts = Counter(bytes_data)
                            entropy = 0.0
                            
                            for count in counts.values():
                                p = count / len(bytes_data)
                                if p > 0:
                                    entropy -= p * np.log2(p)
                            
                            total_entropy += entropy * size
                            total_size += size
                        except ValueError:
                            pass
            
            return total_entropy / max(1, total_size)
            
        except Exception as e:
            self.logger.warning(f"File entropy calculation failed: {e}")
            return 0.0
    
    def _count_sections(self) -> int:
        """Count total sections"""
        try:
            if not self.r2:
                return 0
            
            sections = self.r2.cmdj("iSj") or []
            return len(sections)
            
        except Exception as e:
            self.logger.warning(f"Section counting failed: {e}")
            return 0
    
    def _calculate_packed_section_ratio(self) -> float:
        """Calculate ratio of packed/high-entropy sections"""
        try:
            if not self.r2:
                return 0.0
            
            sections = self.r2.cmdj("iSj") or []
            if not sections:
                return 0.0
            
            packed_count = 0
            
            for section in sections:
                size = section.get('vsize', 0)
                addr = section.get('vaddr', 0)
                
                if size > 100:  # Only check reasonably sized sections
                    # Sample data and check entropy
                    sample_size = min(size, 512)
                    data = self.r2.cmd(f"p8 {sample_size} @ {addr}")
                    
                    if data:
                        try:
                            bytes_data = bytes.fromhex(data)
                            
                            # Calculate entropy
                            from collections import Counter
                            counts = Counter(bytes_data)
                            entropy = 0.0
                            
                            for count in counts.values():
                                p = count / len(bytes_data)
                                if p > 0:
                                    entropy -= p * np.log2(p)
                            
                            # High entropy suggests packing
                            if entropy > 7.0:
                                packed_count += 1
                        except ValueError:
                            pass
            
            return packed_count / len(sections)
            
        except Exception as e:
            self.logger.warning(f"Packed section ratio calculation failed: {e}")
            return 0.0