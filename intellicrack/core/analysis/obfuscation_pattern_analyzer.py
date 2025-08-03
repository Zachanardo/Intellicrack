"""
Comprehensive Obfuscation Pattern Recognition System

Advanced detection and analysis of code obfuscation techniques used in protected software.
Integrates multiple detection engines for control flow, data, and API call obfuscation.

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

import json
import logging
import numpy as np
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ...utils.logger import get_logger
from .unified_model import (
    AnalysisSource, AnalysisPhase, ConfidenceLevel, AnalysisEvent,
    ObfuscationAnalysis, ObfuscationPattern as UnifiedObfuscationPattern,
    ObfuscationFeatures as UnifiedObfuscationFeatures,
    MLClassificationResult as UnifiedMLClassificationResult
)
from .obfuscation_detectors.ml_obfuscation_classifier import (
    MLObfuscationClassifier, ObfuscationFeatures, ClassificationResult
)

logger = get_logger(__name__)

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False
    logger.warning("r2pipe not available - some obfuscation detection features disabled")

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available - ML-based detection disabled")


class ObfuscationType(Enum):
    """Types of obfuscation techniques"""
    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    OPAQUE_PREDICATES = "opaque_predicates"
    BOGUS_CONTROL_FLOW = "bogus_control_flow"
    JUMP_TABLE_OBFUSCATION = "jump_table_obfuscation"
    FUNCTION_CALL_INDIRECTION = "function_call_indirection"
    INSTRUCTION_SUBSTITUTION = "instruction_substitution"
    METAMORPHIC_CODE = "metamorphic_code"
    POLYMORPHIC_SEQUENCES = "polymorphic_sequences"
    DEAD_CODE_INSERTION = "dead_code_insertion"
    REGISTER_ALLOCATION_OBFUSCATION = "register_allocation_obfuscation"
    STRING_ENCRYPTION = "string_encryption"
    XOR_OBFUSCATION = "xor_obfuscation"
    BASE64_ENCODING = "base64_encoding"
    CUSTOM_ENCODING = "custom_encoding"
    DYNAMIC_STRING_CONSTRUCTION = "dynamic_string_construction"
    RUNTIME_STRING_DECRYPTION = "runtime_string_decryption"
    DYNAMIC_API_LOADING = "dynamic_api_loading"
    API_HASHING = "api_hashing"
    INDIRECT_FUNCTION_CALLS = "indirect_function_calls"
    API_CALL_REDIRECTION = "api_call_redirection"
    IMPORT_TABLE_MANIPULATION = "import_table_manipulation"
    CODE_VIRTUALIZATION = "code_virtualization"
    BYTECODE_INTERPRETATION = "bytecode_interpretation"
    VM_BASED_PROTECTION = "vm_based_protection"
    JIT_COMPILATION = "jit_compilation"
    CUSTOM_INSTRUCTION_SETS = "custom_instruction_sets"


class ObfuscationSeverity(Enum):
    """Severity levels for obfuscation detection"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ObfuscationPattern:
    """Detected obfuscation pattern"""
    type: ObfuscationType
    severity: ObfuscationSeverity
    confidence: float
    addresses: List[int]
    description: str
    indicators: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    detection_method: str = "heuristic"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'type': self.type.value,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'addresses': self.addresses,
            'description': self.description,
            'indicators': self.indicators,
            'metadata': self.metadata,
            'detection_method': self.detection_method
        }


@dataclass
class ControlFlowAnalysis:
    """Control flow obfuscation analysis results"""
    basic_blocks: int
    edges: int
    complexity_score: float
    flattening_indicators: List[str]
    opaque_predicate_candidates: List[Dict[str, Any]]
    bogus_blocks: List[Dict[str, Any]]
    jump_table_anomalies: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'basic_blocks': self.basic_blocks,
            'edges': self.edges,
            'complexity_score': self.complexity_score,
            'flattening_indicators': self.flattening_indicators,
            'opaque_predicate_candidates': self.opaque_predicate_candidates,
            'bogus_blocks': self.bogus_blocks,
            'jump_table_anomalies': self.jump_table_anomalies
        }


@dataclass
class StringObfuscationAnalysis:
    """String and data obfuscation analysis results"""
    total_strings: int
    encrypted_strings: int
    xor_patterns: List[Dict[str, Any]]
    encoding_schemes: List[str]
    dynamic_construction: List[Dict[str, Any]]
    runtime_decryption: List[Dict[str, Any]]
    entropy_analysis: Dict[str, float]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_strings': self.total_strings,
            'encrypted_strings': self.encrypted_strings,
            'xor_patterns': self.xor_patterns,
            'encoding_schemes': self.encoding_schemes,
            'dynamic_construction': self.dynamic_construction,
            'runtime_decryption': self.runtime_decryption,
            'entropy_analysis': self.entropy_analysis
        }


@dataclass
class APIObfuscationAnalysis:
    """API call obfuscation analysis results"""
    total_imports: int
    dynamic_loading_patterns: List[Dict[str, Any]]
    api_hashing_indicators: List[Dict[str, Any]]
    indirect_calls: List[Dict[str, Any]]
    redirection_patterns: List[Dict[str, Any]]
    import_manipulation: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'total_imports': self.total_imports,
            'dynamic_loading_patterns': self.dynamic_loading_patterns,
            'api_hashing_indicators': self.api_hashing_indicators,
            'indirect_calls': self.indirect_calls,
            'redirection_patterns': self.redirection_patterns,
            'import_manipulation': self.import_manipulation
        }


@dataclass
class MLFeatureSet:
    """Machine learning feature set for obfuscation detection"""
    instruction_entropy: float
    string_entropy: float
    control_flow_complexity: float
    api_call_patterns: List[float]
    register_usage_patterns: List[float]
    branching_patterns: List[float]
    instruction_frequencies: Dict[str, int]
    
    def to_feature_vector(self) -> np.ndarray:
        """Convert to feature vector for ML algorithms"""
        features = [
            self.instruction_entropy,
            self.string_entropy,
            self.control_flow_complexity
        ]
        features.extend(self.api_call_patterns)
        features.extend(self.register_usage_patterns)
        features.extend(self.branching_patterns)
        
        # Add top 50 instruction frequencies
        sorted_instructions = sorted(
            self.instruction_frequencies.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        for i, (instr, freq) in enumerate(sorted_instructions[:50]):
            features.append(freq)
        
        # Pad to fixed size
        while len(features) < 100:
            features.append(0.0)
            
        return np.array(features[:100])


class ObfuscationPatternAnalyzer:
    """Comprehensive obfuscation pattern recognition system"""
    
    def __init__(self, binary_path: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        """Initialize obfuscation pattern analyzer
        
        Args:
            binary_path: Path to binary file to analyze
            config: Configuration options
        """
        self.binary_path = binary_path
        self.config = config or {}
        self.logger = logger
        
        # Analysis components
        self.r2 = None
        self.analysis_results = {}
        self.ml_models = {}
        self.ml_classifier = None
        
        # Configuration
        self.enable_ml = self.config.get('enable_ml', SKLEARN_AVAILABLE)
        self.parallel_analysis = self.config.get('parallel_analysis', True)
        self.max_workers = self.config.get('max_workers', 4)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.6)
        
        # Initialize ML models if available
        if self.enable_ml and SKLEARN_AVAILABLE:
            self._initialize_ml_models()
            self.ml_classifier = MLObfuscationClassifier()
        
        # Pattern databases
        self._load_pattern_databases()
        
    def _initialize_ml_models(self):
        """Initialize machine learning models for obfuscation detection"""
        try:
            # Anomaly detection model for identifying unusual patterns
            self.ml_models['anomaly_detector'] = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Clustering model for grouping similar patterns
            self.ml_models['pattern_clusterer'] = DBSCAN(
                eps=0.5,
                min_samples=3
            )
            
            # Feature scaler
            self.ml_models['feature_scaler'] = StandardScaler()
            
            self.logger.info("ML models initialized for obfuscation detection")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
            self.enable_ml = False
    
    def _load_pattern_databases(self):
        """Load known obfuscation pattern databases"""
        self.known_patterns = {
            'control_flow_flattening': {
                'signatures': [
                    'dispatcher block pattern',
                    'state variable usage',
                    'unconditional jumps to dispatcher'
                ],
                'indicators': [
                    'single large basic block',
                    'many indirect jumps',
                    'state machine pattern'
                ]
            },
            'opaque_predicates': {
                'signatures': [
                    'always true conditions',
                    'always false conditions',
                    'contextual predicates'
                ],
                'indicators': [
                    'redundant comparisons',
                    'unreachable code paths',
                    'complex boolean expressions'
                ]
            },
            'api_hashing': {
                'signatures': [
                    'hash calculation loops',
                    'string to hash conversion',
                    'hash table lookups'
                ],
                'indicators': [
                    'GetProcAddress alternatives',
                    'LoadLibrary alternatives',
                    'hash comparison patterns'
                ]
            },
            'string_encryption': {
                'signatures': [
                    'XOR decryption loops',
                    'key scheduling algorithms',
                    'encrypted data sections'
                ],
                'indicators': [
                    'high entropy strings',
                    'decryption routines',
                    'runtime string building'
                ]
            }
        }        
    def analyze(self, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Perform comprehensive obfuscation pattern analysis
        
        Args:
            binary_path: Optional binary path to analyze
            
        Returns:
            Complete obfuscation analysis results
        """
        if binary_path:
            self.binary_path = binary_path
            
        if not self.binary_path:
            raise ValueError("No binary path specified for analysis")
        
        binary_path = Path(self.binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        start_time = time.time()
        self.logger.info(f"Starting obfuscation pattern analysis: {binary_path}")
        
        try:
            # Initialize radare2 session
            if R2_AVAILABLE:
                self._initialize_r2_session()
            
            # Perform parallel analysis
            if self.parallel_analysis:
                results = self._parallel_analysis()
            else:
                results = self._sequential_analysis()
            
            # ML-based enhancement
            if self.enable_ml:
                results = self._enhance_with_ml(results)
            
            # Generate comprehensive report
            analysis_time = time.time() - start_time
            final_results = self._generate_analysis_report(results, analysis_time)
            
            self.logger.info(f"Obfuscation analysis completed in {analysis_time:.2f}s")
            return final_results
            
        except Exception as e:
            self.logger.error(f"Obfuscation analysis failed: {e}")
            return {
                'error': str(e),
                'file_path': str(binary_path),
                'analysis_time': time.time() - start_time
            }
        finally:
            self._cleanup_session()
    
    def _initialize_r2_session(self):
        """Initialize radare2 session for analysis"""
        try:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd("aaa")  # Analyze all
            self.logger.debug("Radare2 session initialized")
        except Exception as e:
            self.logger.warning(f"Failed to initialize r2 session: {e}")
            self.r2 = None
    
    def _parallel_analysis(self) -> Dict[str, Any]:
        """Perform parallel obfuscation analysis"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit analysis tasks
            future_to_analysis = {
                executor.submit(self._analyze_control_flow): 'control_flow',
                executor.submit(self._analyze_code_transformations): 'code_transformations',
                executor.submit(self._analyze_string_obfuscation): 'string_obfuscation',
                executor.submit(self._analyze_api_obfuscation): 'api_obfuscation',
                executor.submit(self._analyze_advanced_techniques): 'advanced_techniques'
            }
            
            # Collect results
            for future in as_completed(future_to_analysis):
                analysis_type = future_to_analysis[future]
                try:
                    result = future.result()
                    results[analysis_type] = result
                    self.logger.debug(f"Completed {analysis_type} analysis")
                except Exception as e:
                    self.logger.error(f"Failed {analysis_type} analysis: {e}")
                    results[analysis_type] = {'error': str(e)}
        
        return results
    
    def _sequential_analysis(self) -> Dict[str, Any]:
        """Perform sequential obfuscation analysis"""
        results = {}
        
        analyses = [
            ('control_flow', self._analyze_control_flow),
            ('code_transformations', self._analyze_code_transformations),
            ('string_obfuscation', self._analyze_string_obfuscation),
            ('api_obfuscation', self._analyze_api_obfuscation),
            ('advanced_techniques', self._analyze_advanced_techniques)
        ]
        
        for name, analysis_func in analyses:
            try:
                results[name] = analysis_func()
                self.logger.debug(f"Completed {name} analysis")
            except Exception as e:
                self.logger.error(f"Failed {name} analysis: {e}")
                results[name] = {'error': str(e)}
        
        return results
    
    def _analyze_control_flow(self) -> ControlFlowAnalysis:
        """Analyze control flow obfuscation patterns"""
        self.logger.debug("Analyzing control flow obfuscation")
        
        basic_blocks = 0
        edges = 0
        complexity_score = 0.0
        flattening_indicators = []
        opaque_predicate_candidates = []
        bogus_blocks = []
        jump_table_anomalies = []
        
        if self.r2:
            try:
                # Get function list
                functions = self.r2.cmdj("aflj") or []
                
                for func in functions:
                    func_addr = func.get('offset', 0)
                    
                    # Analyze basic blocks
                    blocks = self.r2.cmdj(f"afbj @ {func_addr}") or []
                    basic_blocks += len(blocks)
                    
                    # Calculate edges and complexity
                    for block in blocks:
                        jump_addr = block.get('jump')
                        fail_addr = block.get('fail')
                        if jump_addr:
                            edges += 1
                        if fail_addr:
                            edges += 1
                    
                    # Check for control flow flattening
                    if self._detect_control_flow_flattening(func_addr, blocks):
                        flattening_indicators.append(f"Function at 0x{func_addr:x}")
                    
                    # Detect opaque predicates
                    opaque_predicates = self._detect_opaque_predicates(func_addr, blocks)
                    opaque_predicate_candidates.extend(opaque_predicates)
                    
                    # Identify bogus control flow
                    bogus = self._detect_bogus_control_flow(func_addr, blocks)
                    bogus_blocks.extend(bogus)
                    
                    # Check jump table anomalies
                    jump_anomalies = self._detect_jump_table_anomalies(func_addr)
                    jump_table_anomalies.extend(jump_anomalies)
                
                # Calculate overall complexity score
                if basic_blocks > 0:
                    complexity_score = edges / basic_blocks
                
            except Exception as e:
                self.logger.error(f"Control flow analysis error: {e}")
        
        return ControlFlowAnalysis(
            basic_blocks=basic_blocks,
            edges=edges,
            complexity_score=complexity_score,
            flattening_indicators=flattening_indicators,
            opaque_predicate_candidates=opaque_predicate_candidates,
            bogus_blocks=bogus_blocks,
            jump_table_anomalies=jump_table_anomalies
        )
    
    def _detect_control_flow_flattening(self, func_addr: int, blocks: List[Dict]) -> bool:
        """Detect control flow flattening patterns"""
        if len(blocks) < 3:
            return False
        
        # Look for dispatcher pattern
        dispatcher_candidates = 0
        state_variable_usage = 0
        
        for block in blocks:
            # Check for switch-like patterns
            if self.r2:
                disasm = self.r2.cmd(f"pdf @ {block.get('addr', 0)}")
                
                # Look for dispatcher indicators
                if any(indicator in disasm.lower() for indicator in 
                       ['switch', 'jmp', 'case', 'default']):
                    dispatcher_candidates += 1
                
                # Look for state variable patterns
                if any(pattern in disasm.lower() for pattern in 
                       ['mov', 'cmp', 'state', 'var']):
                    state_variable_usage += 1
        
        # Heuristic: if more than 50% blocks look like dispatchers
        return dispatcher_candidates > len(blocks) * 0.5
    
    def _detect_opaque_predicates(self, func_addr: int, blocks: List[Dict]) -> List[Dict[str, Any]]:
        """Detect opaque predicate patterns"""
        candidates = []
        
        if not self.r2:
            return candidates
        
        for block in blocks:
            block_addr = block.get('addr', 0)
            
            # Get disassembly for the block
            disasm = self.r2.cmd(f"pdb @ {block_addr}")
            lines = disasm.split('\n')
            
            # Look for suspicious comparison patterns
            for i, line in enumerate(lines):
                if any(cmp in line.lower() for cmp in ['cmp', 'test']):
                    # Check for always true/false patterns
                    if self._is_opaque_predicate(line, lines[i:i+3]):
                        candidates.append({
                            'address': block_addr,
                            'type': 'opaque_predicate',
                            'pattern': line.strip(),
                            'confidence': 0.7
                        })
        
        return candidates
    
    def _is_opaque_predicate(self, cmp_line: str, context: List[str]) -> bool:
        """Check if a comparison is likely an opaque predicate"""
        # Simple heuristics for opaque predicates
        patterns = [
            # Always true patterns
            ('cmp', 'eax', 'eax'),  # cmp eax, eax (always equal)
            ('test', 'eax', 'eax'),  # test eax, eax with eax = eax
            # Mathematical identities
            ('x*x', '>=', '0'),  # x^2 >= 0 always true
            ('|x|', '>=', '0'),  # |x| >= 0 always true
        ]
        
        cmp_lower = cmp_line.lower()
        
        # Check for self-comparison
        if 'cmp' in cmp_lower:
            parts = cmp_lower.split()
            if len(parts) >= 3:
                reg1 = parts[-2].rstrip(',')
                reg2 = parts[-1]
                if reg1 == reg2:
                    return True
        
        # Check for test self
        if 'test' in cmp_lower:
            parts = cmp_lower.split()
            if len(parts) >= 3:
                reg1 = parts[-2].rstrip(',')
                reg2 = parts[-1]
                if reg1 == reg2:
                    return True
        
        return False
    
    def _detect_bogus_control_flow(self, func_addr: int, blocks: List[Dict]) -> List[Dict[str, Any]]:
        """Detect bogus control flow insertion"""
        bogus_blocks = []
        
        if not self.r2:
            return bogus_blocks
        
        for block in blocks:
            block_addr = block.get('addr', 0)
            block_size = block.get('size', 0)
            
            # Check for unreachable blocks
            if self._is_unreachable_block(block_addr):
                bogus_blocks.append({
                    'address': block_addr,
                    'size': block_size,
                    'type': 'unreachable_block',
                    'confidence': 0.8
                })
            
            # Check for dead code patterns
            if self._contains_dead_code(block_addr):
                bogus_blocks.append({
                    'address': block_addr,
                    'size': block_size,
                    'type': 'dead_code',
                    'confidence': 0.6
                })
        
        return bogus_blocks
    
    def _is_unreachable_block(self, block_addr: int) -> bool:
        """Check if a block is unreachable"""
        if not self.r2:
            return False
        
        # Get cross-references to this block
        xrefs = self.r2.cmdj(f"axtj @ {block_addr}") or []
        
        # If no xrefs and not function start, likely unreachable
        if not xrefs:
            # Check if it's a function start
            func_info = self.r2.cmdj(f"afij @ {block_addr}")
            if not func_info:
                return True
        
        return False
    
    def _contains_dead_code(self, block_addr: int) -> bool:
        """Check if block contains dead code patterns"""
        if not self.r2:
            return False
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        
        # Look for dead code indicators
        dead_code_patterns = [
            'nop',  # No operation
            'int3',  # Breakpoint
            'ud2',   # Undefined instruction
            'hlt',   # Halt
        ]
        
        lines = disasm.split('\n')
        dead_instructions = 0
        
        for line in lines:
            if any(pattern in line.lower() for pattern in dead_code_patterns):
                dead_instructions += 1
        
        # If more than 30% are dead instructions
        return dead_instructions > len(lines) * 0.3
    
    def _detect_jump_table_anomalies(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect jump table obfuscation"""
        anomalies = []
        
        if not self.r2:
            return anomalies
        
        # Look for switch statements / jump tables
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        
        if 'switch' in disasm.lower() or 'jmp' in disasm.lower():
            # Analyze jump table structure
            jump_refs = self.r2.cmdj(f"axtj @ {func_addr}") or []
            
            # Check for obfuscated jump tables
            if len(jump_refs) > 10:  # Many targets might indicate obfuscation
                anomalies.append({
                    'address': func_addr,
                    'type': 'complex_jump_table',
                    'target_count': len(jump_refs),
                    'confidence': 0.5
                })
        
        return anomalies    def _analyze_code_transformations(self) -> Dict[str, Any]:
        """Analyze code transformation obfuscation patterns"""
        self.logger.debug("Analyzing code transformation obfuscation")
        
        results = {
            'instruction_substitutions': [],
            'metamorphic_patterns': [],
            'polymorphic_sequences': [],
            'dead_code_insertions': [],
            'register_obfuscation': []
        }
        
        if not self.r2:
            return results
        
        try:
            # Get all functions
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                
                # Analyze instruction patterns
                inst_patterns = self._detect_instruction_substitution(func_addr)
                results['instruction_substitutions'].extend(inst_patterns)
                
                # Check for metamorphic code
                metamorphic = self._detect_metamorphic_code(func_addr)
                results['metamorphic_patterns'].extend(metamorphic)
                
                # Detect polymorphic sequences
                polymorphic = self._detect_polymorphic_sequences(func_addr)
                results['polymorphic_sequences'].extend(polymorphic)
                
                # Find dead code insertions
                dead_code = self._detect_dead_code_insertions(func_addr)
                results['dead_code_insertions'].extend(dead_code)
                
                # Analyze register allocation obfuscation
                reg_obfuscation = self._detect_register_obfuscation(func_addr)
                results['register_obfuscation'].extend(reg_obfuscation)
        
        except Exception as e:
            self.logger.error(f"Code transformation analysis error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_instruction_substitution(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect instruction substitution patterns"""
        substitutions = []
        
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        lines = disasm.split('\n')
        
        # Common instruction substitution patterns
        substitution_patterns = {
            'mov_zero': {
                'original': ['mov reg, 0'],
                'substitutes': ['xor reg, reg', 'sub reg, reg', 'and reg, 0']
            },
            'increment': {
                'original': ['inc reg'],
                'substitutes': ['add reg, 1', 'lea reg, [reg+1]']
            },
            'clear_register': {
                'original': ['xor reg, reg'],
                'substitutes': ['mov reg, 0', 'sub reg, reg']
            }
        }
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Check for complex instruction sequences that could be simple operations
            if self._is_complex_substitution(line_clean, lines[i:i+3]):
                substitutions.append({
                    'address': self._extract_address(line),
                    'type': 'instruction_substitution',
                    'pattern': line_clean,
                    'confidence': 0.6
                })
        
        return substitutions
    
    def _is_complex_substitution(self, instruction: str, context: List[str]) -> bool:
        """Check if instruction sequence is unnecessarily complex"""
        # Look for overly complex ways to do simple operations
        complex_patterns = [
            # Complex zero setting
            ('push', 'pop', 'xor'),
            # Complex addition through multiple operations
            ('lea', 'add', 'sub'),
            # Unnecessary register moves
            ('mov', 'mov', 'mov')
        ]
        
        context_lower = [line.strip().lower() for line in context[:3]]
        
        for pattern in complex_patterns:
            if len(context_lower) >= len(pattern):
                if all(op in ' '.join(context_lower[:len(pattern)]) for op in pattern):
                    return True
        
        return False
    
    def _detect_metamorphic_code(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect metamorphic code patterns"""
        metamorphic_patterns = []
        
        # Get function entropy and instruction diversity
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        instructions = self._extract_instructions(disasm)
        
        if len(instructions) < 10:
            return metamorphic_patterns
        
        # Calculate instruction diversity
        unique_instructions = set(instructions)
        diversity_ratio = len(unique_instructions) / len(instructions)
        
        # High diversity might indicate metamorphic code
        if diversity_ratio > 0.8:
            metamorphic_patterns.append({
                'address': func_addr,
                'type': 'high_instruction_diversity',
                'diversity_ratio': diversity_ratio,
                'confidence': 0.7
            })
        
        # Look for instruction pattern variations
        pattern_variations = self._find_pattern_variations(instructions)
        if pattern_variations:
            metamorphic_patterns.extend(pattern_variations)
        
        return metamorphic_patterns
    
    def _detect_polymorphic_sequences(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect polymorphic instruction sequences"""
        polymorphic_sequences = []
        
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        instructions = self._extract_instructions(disasm)
        
        # Look for equivalent instruction sequences
        for i in range(len(instructions) - 3):
            sequence = instructions[i:i+3]
            
            # Check if this sequence has functional equivalents elsewhere
            if self._has_equivalent_sequences(sequence, instructions):
                polymorphic_sequences.append({
                    'address': self._extract_address_from_sequence(disasm, i),
                    'type': 'polymorphic_sequence',
                    'sequence': sequence,
                    'confidence': 0.6
                })
        
        return polymorphic_sequences
    
    def _detect_dead_code_insertions(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect dead code insertion patterns"""
        dead_code_insertions = []
        
        # Get control flow graph
        cfg = self.r2.cmdj(f"agfj @ {func_addr}")
        if not cfg:
            return dead_code_insertions
        
        # Analyze each basic block for dead code
        for block in cfg.get('blocks', []):
            block_addr = block.get('offset', 0)
            
            # Check if block is reachable
            if not self._is_block_reachable(block_addr, cfg):
                dead_code_insertions.append({
                    'address': block_addr,
                    'type': 'unreachable_dead_code',
                    'size': block.get('size', 0),
                    'confidence': 0.9
                })
            
            # Check for NOP sleds and useless operations
            useless_ops = self._detect_useless_operations(block_addr)
            dead_code_insertions.extend(useless_ops)
        
        return dead_code_insertions
    
    def _detect_register_obfuscation(self, func_addr: int) -> List[Dict[str, Any]]:
        """Detect register allocation obfuscation"""
        reg_obfuscation = []
        
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        lines = disasm.split('\n')
        
        # Track register usage patterns
        register_usage = {}
        unnecessary_moves = []
        
        for line in lines:
            # Extract register operations
            if any(op in line.lower() for op in ['mov', 'push', 'pop']):
                registers = self._extract_registers(line)
                
                for reg in registers:
                    register_usage[reg] = register_usage.get(reg, 0) + 1
                
                # Check for unnecessary register moves
                if self._is_unnecessary_move(line):
                    unnecessary_moves.append({
                        'address': self._extract_address(line),
                        'instruction': line.strip(),
                        'type': 'unnecessary_register_move'
                    })
        
        # Analyze register usage patterns
        if register_usage:
            # Calculate register distribution entropy
            total_usage = sum(register_usage.values())
            entropy = -sum((count / total_usage) * np.log2(count / total_usage) 
                          for count in register_usage.values() if count > 0)
            
            # High entropy might indicate register obfuscation
            if entropy > 3.0:
                reg_obfuscation.append({
                    'address': func_addr,
                    'type': 'high_register_entropy',
                    'entropy': entropy,
                    'confidence': 0.6
                })
        
        # Add unnecessary moves
        reg_obfuscation.extend(unnecessary_moves)
        
        return reg_obfuscation
    
    def _analyze_string_obfuscation(self) -> StringObfuscationAnalysis:
        """Analyze string and data obfuscation patterns"""
        self.logger.debug("Analyzing string obfuscation")
        
        total_strings = 0
        encrypted_strings = 0
        xor_patterns = []
        encoding_schemes = []
        dynamic_construction = []
        runtime_decryption = []
        entropy_analysis = {}
        
        if self.r2:
            try:
                # Get all strings
                strings = self.r2.cmdj("izj") or []
                total_strings = len(strings)
                
                for string_info in strings:
                    string_data = string_info.get('string', '')
                    string_addr = string_info.get('vaddr', 0)
                    
                    # Calculate string entropy
                    entropy = self._calculate_string_entropy(string_data)
                    
                    # High entropy indicates possible encryption
                    if entropy > 6.5:
                        encrypted_strings += 1
                        entropy_analysis[f"0x{string_addr:x}"] = entropy
                    
                    # Check for encoding schemes
                    encoding = self._detect_encoding_scheme(string_data)
                    if encoding and encoding not in encoding_schemes:
                        encoding_schemes.append(encoding)
                    
                    # Look for XOR patterns
                    xor_pattern = self._detect_xor_pattern(string_data, string_addr)
                    if xor_pattern:
                        xor_patterns.append(xor_pattern)
                
                # Analyze dynamic string construction
                dynamic_construction = self._detect_dynamic_string_construction()
                
                # Find runtime decryption routines
                runtime_decryption = self._detect_runtime_string_decryption()
                
            except Exception as e:
                self.logger.error(f"String analysis error: {e}")
        
        return StringObfuscationAnalysis(
            total_strings=total_strings,
            encrypted_strings=encrypted_strings,
            xor_patterns=xor_patterns,
            encoding_schemes=encoding_schemes,
            dynamic_construction=dynamic_construction,
            runtime_decryption=runtime_decryption,
            entropy_analysis=entropy_analysis
        )
    
    def _calculate_string_entropy(self, string_data: str) -> float:
        """Calculate Shannon entropy of string"""
        if not string_data:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in string_data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        length = len(string_data)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _detect_encoding_scheme(self, string_data: str) -> Optional[str]:
        """Detect encoding scheme used for string"""
        import base64
        import re
        
        # Check for Base64
        try:
            if re.match(r'^[A-Za-z0-9+/]*={0,2}$', string_data) and len(string_data) % 4 == 0:
                base64.b64decode(string_data)
                return "base64"
        except:
            pass
        
        # Check for hex encoding
        if re.match(r'^[0-9a-fA-F]+$', string_data) and len(string_data) % 2 == 0:
            return "hexadecimal"
        
        # Check for URL encoding
        if '%' in string_data and re.search(r'%[0-9a-fA-F]{2}', string_data):
            return "url_encoding"
        
        # Check for custom encoding patterns
        if self._is_custom_encoding(string_data):
            return "custom_encoding"
        
        return None
    
    def _is_custom_encoding(self, string_data: str) -> bool:
        """Check for custom encoding patterns"""
        # Look for patterns that suggest custom encoding
        
        # Character substitution patterns
        if len(set(string_data)) < len(string_data) * 0.3:
            return True  # Low character diversity
        
        # Repeated patterns
        if len(string_data) > 10:
            for i in range(2, min(len(string_data) // 2, 8)):
                pattern = string_data[:i]
                if string_data.count(pattern) > 3:
                    return True
        
        return False    def _detect_xor_pattern(self, string_data: str, string_addr: int) -> Optional[Dict[str, Any]]:
        """Detect XOR obfuscation patterns"""
        if len(string_data) < 4:
            return None
        
        # Convert string to bytes for analysis
        try:
            data_bytes = string_data.encode('latin-1')
        except:
            return None
        
        # Try common XOR keys
        common_keys = [0x01, 0x13, 0x37, 0x42, 0xAA, 0xFF]
        
        for key in common_keys:
            decoded = bytes(b ^ key for b in data_bytes)
            
            # Check if decoded data looks like readable text
            if self._is_likely_text(decoded):
                return {
                    'address': string_addr,
                    'key': key,
                    'original': string_data[:50],
                    'decoded': decoded.decode('latin-1', errors='ignore')[:50],
                    'confidence': 0.8
                }
        
        # Check for single-byte XOR with pattern analysis
        key_candidate = self._find_xor_key_candidate(data_bytes)
        if key_candidate:
            return {
                'address': string_addr,
                'key': key_candidate,
                'type': 'single_byte_xor',
                'confidence': 0.6
            }
        
        return None
    
    def _is_likely_text(self, data: bytes) -> bool:
        """Check if decoded data looks like readable text"""
        try:
            text = data.decode('ascii')
            # Check for printable characters
            printable_ratio = sum(1 for c in text if c.isprintable()) / len(text)
            return printable_ratio > 0.8
        except:
            return False
    
    def _find_xor_key_candidate(self, data_bytes: bytes) -> Optional[int]:
        """Find potential XOR key using frequency analysis"""
        if len(data_bytes) < 8:
            return None
        
        # Assume the most common byte when XORed should produce space (0x20)
        byte_counts = {}
        for byte in data_bytes:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        most_common_byte = max(byte_counts, key=byte_counts.get)
        
        # Try XOR with space character
        key_candidate = most_common_byte ^ 0x20
        
        # Verify this key produces reasonable results
        decoded = bytes(b ^ key_candidate for b in data_bytes)
        if self._is_likely_text(decoded):
            return key_candidate
        
        return None
    
    def _detect_dynamic_string_construction(self) -> List[Dict[str, Any]]:
        """Detect dynamic string construction patterns"""
        dynamic_patterns = []
        
        if not self.r2:
            return dynamic_patterns
        
        # Look for string building functions
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for string concatenation patterns
            if self._has_string_concatenation(disasm):
                dynamic_patterns.append({
                    'address': func_addr,
                    'type': 'string_concatenation',
                    'confidence': 0.7
                })
            
            # Look for character-by-character construction
            if self._has_char_by_char_construction(disasm):
                dynamic_patterns.append({
                    'address': func_addr,
                    'type': 'char_by_char_construction',
                    'confidence': 0.8
                })
        
        return dynamic_patterns
    
    def _has_string_concatenation(self, disasm: str) -> bool:
        """Check for string concatenation patterns"""
        concat_indicators = [
            'strcat', 'strncat', 'sprintf', 'snprintf',
            'StringCchCat', 'StringCbCat'
        ]
        
        return any(indicator in disasm for indicator in concat_indicators)
    
    def _has_char_by_char_construction(self, disasm: str) -> bool:
        """Check for character-by-character string construction"""
        # Look for loops with character operations
        lines = disasm.split('\n')
        
        has_loop = any('loop' in line.lower() or 'jmp' in line.lower() 
                      for line in lines)
        has_char_ops = any('mov byte' in line.lower() or 'stosb' in line.lower() 
                          for line in lines)
        
        return has_loop and has_char_ops
    
    def _detect_runtime_string_decryption(self) -> List[Dict[str, Any]]:
        """Detect runtime string decryption routines"""
        decryption_patterns = []
        
        if not self.r2:
            return decryption_patterns
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for decryption indicators
            if self._has_decryption_patterns(disasm):
                decryption_patterns.append({
                    'address': func_addr,
                    'type': 'runtime_decryption',
                    'indicators': self._extract_decryption_indicators(disasm),
                    'confidence': 0.8
                })
        
        return decryption_patterns
    
    def _has_decryption_patterns(self, disasm: str) -> bool:
        """Check for decryption patterns in disassembly"""
        decryption_indicators = [
            'xor',  # XOR operations
            'rol', 'ror',  # Rotation operations
            'add', 'sub',  # Addition/subtraction
            'key',  # References to keys
            'decrypt', 'decode'  # Explicit references
        ]
        
        indicator_count = sum(1 for indicator in decryption_indicators 
                             if indicator in disasm.lower())
        
        # If multiple indicators present, likely decryption
        return indicator_count >= 3
    
    def _extract_decryption_indicators(self, disasm: str) -> List[str]:
        """Extract specific decryption indicators"""
        indicators = []
        
        if 'xor' in disasm.lower():
            indicators.append('XOR_operations')
        if any(op in disasm.lower() for op in ['rol', 'ror']):
            indicators.append('rotation_operations')
        if 'key' in disasm.lower():
            indicators.append('key_references')
        if any(term in disasm.lower() for term in ['decrypt', 'decode']):
            indicators.append('explicit_decryption_calls')
        
        return indicators
    
    def _analyze_api_obfuscation(self) -> APIObfuscationAnalysis:
        """Analyze API call obfuscation patterns"""
        self.logger.debug("Analyzing API obfuscation")
        
        total_imports = 0
        dynamic_loading_patterns = []
        api_hashing_indicators = []
        indirect_calls = []
        redirection_patterns = []
        import_manipulation = []
        
        if self.r2:
            try:
                # Get import information
                imports = self.r2.cmdj("iij") or []
                total_imports = len(imports)
                
                # Analyze import table for manipulation
                import_manipulation = self._detect_import_table_manipulation(imports)
                
                # Look for dynamic loading patterns
                dynamic_loading_patterns = self._detect_dynamic_api_loading()
                
                # Detect API hashing
                api_hashing_indicators = self._detect_api_hashing()
                
                # Find indirect call patterns
                indirect_calls = self._detect_indirect_calls()
                
                # Analyze API call redirection
                redirection_patterns = self._detect_api_redirection()
                
            except Exception as e:
                self.logger.error(f"API analysis error: {e}")
        
        return APIObfuscationAnalysis(
            total_imports=total_imports,
            dynamic_loading_patterns=dynamic_loading_patterns,
            api_hashing_indicators=api_hashing_indicators,
            indirect_calls=indirect_calls,
            redirection_patterns=redirection_patterns,
            import_manipulation=import_manipulation
        )
    
    def _detect_import_table_manipulation(self, imports: List[Dict]) -> List[str]:
        """Detect import table manipulation"""
        manipulations = []
        
        # Check for suspicious import patterns
        import_names = [imp.get('name', '') for imp in imports]
        
        # Look for dynamic loading functions
        dynamic_loading_apis = [
            'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress',
            'LdrLoadDll', 'LdrGetProcedureAddress'
        ]
        
        for api in dynamic_loading_apis:
            if any(api in name for name in import_names):
                manipulations.append(f"dynamic_loading_{api}")
        
        # Check for missing common imports (might be hidden)
        common_apis = ['CreateFile', 'ReadFile', 'WriteFile', 'MessageBox']
        missing_common = [api for api in common_apis 
                         if not any(api in name for name in import_names)]
        
        if len(missing_common) > 2:
            manipulations.append("missing_common_apis")
        
        return manipulations
    
    def _detect_dynamic_api_loading(self) -> List[Dict[str, Any]]:
        """Detect dynamic API loading patterns"""
        patterns = []
        
        if not self.r2:
            return patterns
        
        # Search for LoadLibrary and GetProcAddress usage
        loadlib_refs = self.r2.cmd("axt LoadLibrary")
        getproc_refs = self.r2.cmd("axt GetProcAddress")
        
        if loadlib_refs or getproc_refs:
            # Analyze usage patterns
            functions = self.r2.cmdj("aflj") or []
            
            for func in functions:
                func_addr = func.get('offset', 0)
                disasm = self.r2.cmd(f"pdf @ {func_addr}")
                
                if 'LoadLibrary' in disasm and 'GetProcAddress' in disasm:
                    patterns.append({
                        'address': func_addr,
                        'type': 'dynamic_api_resolution',
                        'has_loadlibrary': True,
                        'has_getprocaddress': True,
                        'confidence': 0.9
                    })
        
        return patterns
    
    def _detect_api_hashing(self) -> List[Dict[str, Any]]:
        """Detect API hashing patterns"""
        hashing_indicators = []
        
        if not self.r2:
            return hashing_indicators
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for hash calculation patterns
            if self._has_hash_calculation(disasm):
                # Check if it's followed by API resolution
                if self._has_api_resolution_after_hash(disasm):
                    hashing_indicators.append({
                        'address': func_addr,
                        'type': 'api_hashing',
                        'hash_algorithm': self._identify_hash_algorithm(disasm),
                        'confidence': 0.8
                    })
        
        return hashing_indicators
    
    def _has_hash_calculation(self, disasm: str) -> bool:
        """Check for hash calculation patterns"""
        hash_indicators = [
            'rol', 'ror',  # Rotation operations common in hashes
            'xor',  # XOR operations
            'add', 'imul',  # Arithmetic operations
            'and', 'or'  # Bitwise operations
        ]
        
        # Count hash-related operations
        indicator_count = sum(1 for indicator in hash_indicators 
                             if indicator in disasm.lower())
        
        # Look for loop patterns (hash calculations often loop)
        has_loop = 'loop' in disasm.lower() or 'jmp' in disasm.lower()
        
        return indicator_count >= 3 and has_loop
    
    def _has_api_resolution_after_hash(self, disasm: str) -> bool:
        """Check if hash is followed by API resolution"""
        return any(api in disasm for api in ['GetProcAddress', 'LdrGetProcedureAddress'])
    
    def _identify_hash_algorithm(self, disasm: str) -> str:
        """Identify the hash algorithm being used"""
        # Simple heuristics for common hash algorithms
        if 'rol' in disasm.lower() and 'add' in disasm.lower():
            return "ror13_hash"
        elif 'imul' in disasm.lower():
            return "djb2_hash"
        elif 'xor' in disasm.lower() and 'shl' in disasm.lower():
            return "fnv_hash"
        else:
            return "unknown_hash"    def _detect_indirect_calls(self) -> List[Dict[str, Any]]:
        """Detect indirect function call patterns"""
        indirect_calls = []
        
        if not self.r2:
            return indirect_calls
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for indirect call patterns
            lines = disasm.split('\n')
            for line in lines:
                if self._is_indirect_call(line):
                    indirect_calls.append({
                        'address': self._extract_address(line),
                        'instruction': line.strip(),
                        'type': 'indirect_call',
                        'confidence': 0.7
                    })
        
        return indirect_calls
    
    def _is_indirect_call(self, instruction: str) -> bool:
        """Check if instruction is an indirect call"""
        inst_lower = instruction.lower()
        
        # Look for call through register or memory
        indirect_patterns = [
            'call eax', 'call ebx', 'call ecx', 'call edx',
            'call rax', 'call rbx', 'call rcx', 'call rdx',
            'call dword ptr', 'call qword ptr',
            'call [e', 'call [r'
        ]
        
        return any(pattern in inst_lower for pattern in indirect_patterns)
    
    def _detect_api_redirection(self) -> List[Dict[str, Any]]:
        """Detect API call redirection patterns"""
        redirections = []
        
        if not self.r2:
            return redirections
        
        # Look for API hooks and redirections
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            
            # Check if function is a wrapper/hook
            if self._is_api_wrapper(func_addr):
                redirections.append({
                    'address': func_addr,
                    'type': 'api_wrapper',
                    'confidence': 0.6
                })
        
        return redirections
    
    def _is_api_wrapper(self, func_addr: int) -> bool:
        """Check if function is an API wrapper/hook"""
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        
        # Simple heuristic: short function that calls another function
        lines = [line for line in disasm.split('\n') if line.strip()]
        
        if len(lines) < 10:  # Short function
            # Check if it has a call instruction
            if any('call' in line.lower() for line in lines):
                return True
        
        return False
    
    def _analyze_advanced_techniques(self) -> Dict[str, Any]:
        """Analyze advanced obfuscation techniques"""
        self.logger.debug("Analyzing advanced obfuscation techniques")
        
        results = {
            'code_virtualization': [],
            'bytecode_interpretation': [],
            'vm_based_protection': [],
            'jit_compilation': [],
            'custom_instruction_sets': []
        }
        
        if not self.r2:
            return results
        
        try:
            # Detect code virtualization
            results['code_virtualization'] = self._detect_code_virtualization()
            
            # Look for bytecode interpretation
            results['bytecode_interpretation'] = self._detect_bytecode_interpretation()
            
            # Identify VM-based protection
            results['vm_based_protection'] = self._detect_vm_protection()
            
            # Find JIT compilation indicators
            results['jit_compilation'] = self._detect_jit_compilation()
            
            # Look for custom instruction sets
            results['custom_instruction_sets'] = self._detect_custom_instructions()
            
        except Exception as e:
            self.logger.error(f"Advanced techniques analysis error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _detect_code_virtualization(self) -> List[Dict[str, Any]]:
        """Detect code virtualization patterns"""
        virtualization_patterns = []
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for VM dispatcher patterns
            if self._has_vm_dispatcher_pattern(disasm):
                virtualization_patterns.append({
                    'address': func_addr,
                    'type': 'vm_dispatcher',
                    'confidence': 0.8
                })
            
            # Look for bytecode handler patterns
            if self._has_bytecode_handlers(disasm):
                virtualization_patterns.append({
                    'address': func_addr,
                    'type': 'bytecode_handler',
                    'confidence': 0.7
                })
        
        return virtualization_patterns
    
    def _has_vm_dispatcher_pattern(self, disasm: str) -> bool:
        """Check for VM dispatcher patterns"""
        # VM dispatchers typically have:
        # - Switch-like constructs
        # - Instruction pointer manipulation
        # - Opcode fetching
        
        vm_indicators = [
            'switch', 'case',  # Switch statements
            'fetch', 'opcode',  # Opcode fetching
            'dispatch', 'handler',  # Dispatch mechanisms
            'vm_', 'virt'  # VM-related names
        ]
        
        indicator_count = sum(1 for indicator in vm_indicators 
                             if indicator in disasm.lower())
        
        return indicator_count >= 2
    
    def _has_bytecode_handlers(self, disasm: str) -> bool:
        """Check for bytecode handler patterns"""
        bytecode_indicators = [
            'handler', 'opcode', 'instruction',
            'decode', 'execute', 'interpret'
        ]
        
        return sum(1 for indicator in bytecode_indicators 
                  if indicator in disasm.lower()) >= 2
    
    def _detect_bytecode_interpretation(self) -> List[Dict[str, Any]]:
        """Detect bytecode interpretation patterns"""
        interpretation_patterns = []
        
        # Look for interpreter loops
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            
            if self._has_interpreter_loop(func_addr):
                interpretation_patterns.append({
                    'address': func_addr,
                    'type': 'interpreter_loop',
                    'confidence': 0.8
                })
        
        return interpretation_patterns
    
    def _has_interpreter_loop(self, func_addr: int) -> bool:
        """Check for interpreter loop patterns"""
        # Get control flow graph
        cfg = self.r2.cmdj(f"agfj @ {func_addr}")
        if not cfg:
            return False
        
        blocks = cfg.get('blocks', [])
        
        # Look for loop with many branches (typical of interpreters)
        for block in blocks:
            # Check if block has many outgoing edges
            if len(block.get('ops', [])) > 20:  # Large block
                disasm = self.r2.cmd(f"pdb @ {block.get('offset', 0)}")
                if 'switch' in disasm.lower() or 'jmp' in disasm.lower():
                    return True
        
        return False
    
    def _detect_vm_protection(self) -> List[Dict[str, Any]]:
        """Detect VM-based protection systems"""
        vm_protections = []
        
        # Look for known VM protection signatures
        vm_signatures = {
            'themida': ['Themida', 'VM_', 'TMD'],
            'vmprotect': ['VMProtect', 'VMP', 'Virtual'],
            'code_virtualizer': ['CodeVirtualizer', 'CV_'],
            'enigma': ['Enigma', 'Virtual Box']
        }
        
        # Get all strings
        strings = self.r2.cmdj("izj") or []
        
        for string_info in strings:
            string_data = string_info.get('string', '').lower()
            
            for vm_name, signatures in vm_signatures.items():
                if any(sig.lower() in string_data for sig in signatures):
                    vm_protections.append({
                        'address': string_info.get('vaddr', 0),
                        'type': vm_name,
                        'signature': string_data,
                        'confidence': 0.9
                    })
        
        return vm_protections
    
    def _detect_jit_compilation(self) -> List[Dict[str, Any]]:
        """Detect JIT compilation indicators"""
        jit_indicators = []
        
        # Look for JIT-related functions and memory operations
        jit_patterns = [
            'VirtualAlloc', 'VirtualProtect',  # Memory allocation/protection
            'mmap', 'mprotect',  # Unix equivalents
            'compile', 'jit', 'runtime'  # JIT-related terms
        ]
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_name = func.get('name', '').lower()
            
            if any(pattern in func_name for pattern in jit_patterns):
                jit_indicators.append({
                    'address': func.get('offset', 0),
                    'name': func_name,
                    'type': 'jit_function',
                    'confidence': 0.6
                })
        
        return jit_indicators
    
    def _detect_custom_instructions(self) -> List[Dict[str, Any]]:
        """Detect custom instruction set usage"""
        custom_instructions = []
        
        # Look for unusual instruction patterns
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            # Look for undefined/custom instructions
            if 'invalid' in disasm.lower() or 'undefined' in disasm.lower():
                custom_instructions.append({
                    'address': func_addr,
                    'type': 'custom_instructions',
                    'confidence': 0.5
                })
        
        return custom_instructions
    
    def _enhance_with_ml(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance results using machine learning"""
        if not self.enable_ml or not self.ml_classifier:
            return results
        
        try:
            # Set ML classifier's radare2 session
            if self.r2:
                self.ml_classifier.r2 = self.r2
            
            # Extract comprehensive features
            features = self.ml_classifier.extract_features(self.binary_path)
            
            if features:
                # Perform ML classification
                classification = self.ml_classifier.classify_obfuscation(features)
                
                # Perform similarity analysis
                similarity = self.ml_classifier.analyze_similarity(features)
                
                # Generate automated signature
                if classification:
                    signature = self.ml_classifier.generate_signature(
                        features, classification.obfuscation_type
                    )
                else:
                    signature = None
                
                # Add ML analysis to results
                results['ml_analysis'] = {
                    'features': features.to_dict() if hasattr(features, 'to_dict') else None,
                    'classification': classification.to_dict() if classification else None,
                    'similarity': similarity.to_dict() if similarity else None,
                    'signature': signature,
                    'ml_enabled': True
                }
                
                # Enhance pattern confidence with ML scores
                if classification:
                    self._enhance_pattern_confidence(results, classification)
        
        except Exception as e:
            self.logger.error(f"ML enhancement failed: {e}")
            results['ml_analysis'] = {'error': str(e), 'ml_enabled': False}
        
        return results
    
    def _enhance_pattern_confidence(self, results: Dict[str, Any], classification: ClassificationResult):
        """Enhance pattern detection confidence using ML classification"""
        try:
            ml_confidence = classification.confidence
            ml_type = classification.obfuscation_type
            
            # Map ML obfuscation type to our pattern types
            type_mapping = {
                'control_flow': ['control_flow_flattening', 'opaque_predicates', 'bogus_control_flow'],
                'string_obfuscation': ['string_encryption', 'xor_obfuscation', 'base64_encoding'],
                'api_obfuscation': ['dynamic_api_loading', 'api_hashing', 'indirect_function_calls'],
                'vm_protection': ['code_virtualization', 'bytecode_interpretation', 'vm_based_protection']
            }
            
            # Enhance confidence for related patterns
            for category, pattern_types in type_mapping.items():
                if category in ml_type.lower():
                    for section in results.values():
                        if isinstance(section, dict) and 'patterns' in section:
                            for pattern in section['patterns']:
                                if pattern.get('type') in pattern_types:
                                    # Boost confidence based on ML agreement
                                    original_confidence = pattern.get('confidence', 0.5)
                                    enhanced_confidence = min(1.0, 
                                        (original_confidence + ml_confidence) / 2.0 + 0.1)
                                    pattern['confidence'] = enhanced_confidence
                                    pattern['ml_enhanced'] = True
                                    
        except Exception as e:
            self.logger.warning(f"Pattern confidence enhancement failed: {e}")
    
    def _extract_ml_features(self, results: Dict[str, Any]) -> List[MLFeatureSet]:
        """Extract features for ML analysis"""
        features = []
        
        # Extract features from analysis results
        control_flow = results.get('control_flow', {})
        code_transform = results.get('code_transformations', {})
        string_analysis = results.get('string_obfuscation', {})
        api_analysis = results.get('api_obfuscation', {})
        
        # Create feature set
        if hasattr(control_flow, 'complexity_score'):
            feature_set = MLFeatureSet(
                instruction_entropy=self._calculate_instruction_entropy(),
                string_entropy=self._calculate_average_string_entropy(string_analysis),
                control_flow_complexity=control_flow.complexity_score,
                api_call_patterns=self._extract_api_patterns(api_analysis),
                register_usage_patterns=self._extract_register_patterns(code_transform),
                branching_patterns=self._extract_branching_patterns(control_flow),
                instruction_frequencies=self._get_instruction_frequencies()
            )
            features.append(feature_set)
        
        return features
    
    def _calculate_instruction_entropy(self) -> float:
        """Calculate entropy of instruction distribution"""
        if not self.r2:
            return 0.0
        
        # Get instruction statistics
        inst_stats = {}
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            instructions = self._extract_instructions(disasm)
            for inst in instructions:
                inst_stats[inst] = inst_stats.get(inst, 0) + 1
        
        # Calculate entropy
        total_instructions = sum(inst_stats.values())
        if total_instructions == 0:
            return 0.0
        
        entropy = 0.0
        for count in inst_stats.values():
            probability = count / total_instructions
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy    def _calculate_average_string_entropy(self, string_analysis) -> float:
        """Calculate average string entropy"""
        if hasattr(string_analysis, 'entropy_analysis') and string_analysis.entropy_analysis:
            entropies = list(string_analysis.entropy_analysis.values())
            return sum(entropies) / len(entropies) if entropies else 0.0
        return 0.0
    
    def _extract_api_patterns(self, api_analysis) -> List[float]:
        """Extract API call patterns as feature vector"""
        patterns = [0.0] * 10  # Fixed size feature vector
        
        if hasattr(api_analysis, 'total_imports'):
            patterns[0] = float(api_analysis.total_imports)
            patterns[1] = float(len(api_analysis.dynamic_loading_patterns))
            patterns[2] = float(len(api_analysis.api_hashing_indicators))
            patterns[3] = float(len(api_analysis.indirect_calls))
            patterns[4] = float(len(api_analysis.redirection_patterns))
        
        return patterns
    
    def _extract_register_patterns(self, code_transform) -> List[float]:
        """Extract register usage patterns"""
        patterns = [0.0] * 8  # Fixed size for 8 common registers
        
        # This would need more detailed register analysis
        # For now, return placeholder values
        return patterns
    
    def _extract_branching_patterns(self, control_flow) -> List[float]:
        """Extract branching patterns"""
        patterns = [0.0] * 5
        
        if hasattr(control_flow, 'basic_blocks'):
            patterns[0] = float(control_flow.basic_blocks)
            patterns[1] = float(control_flow.edges)
            patterns[2] = control_flow.complexity_score
            patterns[3] = float(len(control_flow.flattening_indicators))
            patterns[4] = float(len(control_flow.opaque_predicate_candidates))
        
        return patterns
    
    def _get_instruction_frequencies(self) -> Dict[str, int]:
        """Get instruction frequency distribution"""
        frequencies = {}
        
        if not self.r2:
            return frequencies
        
        functions = self.r2.cmdj("aflj") or []
        
        for func in functions:
            func_addr = func.get('offset', 0)
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            instructions = self._extract_instructions(disasm)
            for inst in instructions:
                frequencies[inst] = frequencies.get(inst, 0) + 1
        
        return frequencies
    
    def _detect_anomalies(self, features: List[MLFeatureSet]) -> List[Dict[str, Any]]:
        """Detect anomalies using isolation forest"""
        if not features:
            return []
        
        try:
            # Convert features to matrix
            feature_matrix = np.array([f.to_feature_vector() for f in features])
            
            # Scale features
            scaled_features = self.ml_models['feature_scaler'].fit_transform(feature_matrix)
            
            # Detect anomalies
            anomaly_scores = self.ml_models['anomaly_detector'].fit_predict(scaled_features)
            
            anomalies = []
            for i, score in enumerate(anomaly_scores):
                if score == -1:  # Anomaly detected
                    anomalies.append({
                        'feature_index': i,
                        'anomaly_score': float(score),
                        'confidence': 0.7
                    })
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return []
    
    def _cluster_patterns(self, features: List[MLFeatureSet]) -> List[Dict[str, Any]]:
        """Cluster obfuscation patterns"""
        if not features or len(features) < 3:
            return []
        
        try:
            # Convert features to matrix
            feature_matrix = np.array([f.to_feature_vector() for f in features])
            
            # Scale features
            scaled_features = self.ml_models['feature_scaler'].fit_transform(feature_matrix)
            
            # Perform clustering
            cluster_labels = self.ml_models['pattern_clusterer'].fit_predict(scaled_features)
            
            clusters = []
            unique_labels = set(cluster_labels)
            
            for label in unique_labels:
                if label != -1:  # Ignore noise points
                    cluster_indices = [i for i, l in enumerate(cluster_labels) if l == label]
                    clusters.append({
                        'cluster_id': int(label),
                        'size': len(cluster_indices),
                        'feature_indices': cluster_indices
                    })
            
            return clusters
            
        except Exception as e:
            self.logger.error(f"Pattern clustering failed: {e}")
            return []
    
    def _generate_analysis_report(self, results: Dict[str, Any], analysis_time: float) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        report = {
            'metadata': {
                'file_path': str(self.binary_path),
                'analysis_time': analysis_time,
                'analyzer_version': '1.0.0',
                'timestamp': time.time(),
                'configuration': self.config.copy()
            },
            'summary': self._generate_summary(results),
            'detailed_results': results,
            'patterns_detected': self._extract_detected_patterns(results),
            'severity_assessment': self._assess_severity(results),
            'recommendations': self._generate_recommendations(results)
        }
        
        # Also generate unified model compatible format
        report['unified_model'] = self._convert_to_unified_model(results, analysis_time)
        
        return report
    
    def _convert_to_unified_model(self, results: Dict[str, Any], analysis_time: float) -> ObfuscationAnalysis:
        """Convert analysis results to unified model format"""
        obfuscation_analysis = ObfuscationAnalysis()
        obfuscation_analysis.analysis_duration = analysis_time
        obfuscation_analysis.sources.add(AnalysisSource.OBFUSCATION_ANALYZER)
        
        # Convert patterns from all analysis sections
        self._convert_patterns_to_unified(results, obfuscation_analysis)
        
        # Add ML analysis if available
        ml_analysis = results.get('ml_analysis', {})
        if ml_analysis and not ml_analysis.get('error'):
            self._convert_ml_to_unified(ml_analysis, obfuscation_analysis)
        
        return obfuscation_analysis
    
    def _convert_patterns_to_unified(self, results: Dict[str, Any], unified_analysis: ObfuscationAnalysis):
        """Convert detected patterns to unified model format"""
        pattern_sections = ['control_flow', 'code_transformations', 'string_obfuscation', 
                           'api_obfuscation', 'advanced_techniques']
        
        for section in pattern_sections:
            section_data = results.get(section, {})
            if isinstance(section_data, dict):
                patterns = section_data.get('patterns', [])
                
                for pattern_dict in patterns:
                    if isinstance(pattern_dict, dict):
                        # Convert to unified pattern format
                        unified_pattern = UnifiedObfuscationPattern(
                            type=pattern_dict.get('type', 'unknown'),
                            severity=pattern_dict.get('severity', 'medium'),
                            confidence=pattern_dict.get('confidence', 0.5),
                            addresses=pattern_dict.get('addresses', []),
                            description=pattern_dict.get('description', ''),
                            indicators=pattern_dict.get('indicators', []),
                            detection_method=pattern_dict.get('detection_method', 'heuristic'),
                            metadata=pattern_dict.get('metadata', {})
                        )
                        
                        unified_analysis.add_pattern(unified_pattern, AnalysisSource.OBFUSCATION_ANALYZER)
    
    def _convert_ml_to_unified(self, ml_analysis: Dict[str, Any], unified_analysis: ObfuscationAnalysis):
        """Convert ML analysis to unified model format"""
        unified_analysis.ml_enabled = True
        
        # Convert features
        features_data = ml_analysis.get('features')
        if features_data:
            unified_analysis.ml_features = UnifiedObfuscationFeatures(
                cfg_complexity=features_data.get('cfg_complexity', 0.0),
                cyclomatic_complexity=features_data.get('cyclomatic_complexity', 0),
                basic_block_count=features_data.get('basic_block_count', 0),
                jump_instruction_ratio=features_data.get('jump_instruction_ratio', 0.0),
                conditional_jump_ratio=features_data.get('conditional_jump_ratio', 0.0),
                indirect_jump_count=features_data.get('indirect_jump_count', 0),
                string_entropy=features_data.get('string_entropy', 0.0),
                encrypted_string_ratio=features_data.get('encrypted_string_ratio', 0.0),
                xor_pattern_count=features_data.get('xor_pattern_count', 0),
                base64_pattern_count=features_data.get('base64_pattern_count', 0),
                dynamic_api_ratio=features_data.get('dynamic_api_ratio', 0.0),
                api_hash_count=features_data.get('api_hash_count', 0),
                indirect_call_ratio=features_data.get('indirect_call_ratio', 0.0),
                import_table_entropy=features_data.get('import_table_entropy', 0.0),
                instruction_entropy=features_data.get('instruction_entropy', 0.0),
                nop_instruction_ratio=features_data.get('nop_instruction_ratio', 0.0),
                dead_code_ratio=features_data.get('dead_code_ratio', 0.0),
                polymorphic_pattern_count=features_data.get('polymorphic_pattern_count', 0),
                vm_pattern_count=features_data.get('vm_pattern_count', 0),
                bytecode_section_count=features_data.get('bytecode_section_count', 0),
                handler_function_count=features_data.get('handler_function_count', 0),
                file_entropy=features_data.get('file_entropy', 0.0),
                section_count=features_data.get('section_count', 0),
                packed_section_ratio=features_data.get('packed_section_ratio', 0.0)
            )
        
        # Convert classification
        classification_data = ml_analysis.get('classification')
        if classification_data:
            unified_analysis.ml_classification = UnifiedMLClassificationResult(
                obfuscation_type=classification_data.get('obfuscation_type', 'unknown'),
                confidence=classification_data.get('confidence', 0.0),
                probability_scores=classification_data.get('probability_scores', {}),
                anomaly_score=classification_data.get('anomaly_score', 0.0),
                cluster_id=classification_data.get('cluster_id', -1),
                feature_importance=classification_data.get('feature_importance', {})
            )
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate analysis summary"""
        total_patterns = 0
        high_severity_patterns = 0
        obfuscation_types = set()
        
        # Count patterns from all analysis types
        for analysis_type, analysis_results in results.items():
            if isinstance(analysis_results, dict):
                for key, patterns in analysis_results.items():
                    if isinstance(patterns, list):
                        total_patterns += len(patterns)
                        
                        # Count high severity patterns
                        for pattern in patterns:
                            if isinstance(pattern, dict):
                                if pattern.get('confidence', 0) > 0.7:
                                    high_severity_patterns += 1
                                
                                pattern_type = pattern.get('type', '')
                                if pattern_type:
                                    obfuscation_types.add(pattern_type)
        
        return {
            'total_patterns_detected': total_patterns,
            'high_confidence_patterns': high_severity_patterns,
            'obfuscation_types_found': len(obfuscation_types),
            'types_list': list(obfuscation_types),
            'overall_obfuscation_level': self._calculate_obfuscation_level(results)
        }
    
    def _calculate_obfuscation_level(self, results: Dict[str, Any]) -> str:
        """Calculate overall obfuscation level"""
        total_score = 0
        
        # Weight different types of obfuscation
        weights = {
            'control_flow': 3.0,
            'code_transformations': 2.5,
            'string_obfuscation': 2.0,
            'api_obfuscation': 2.5,
            'advanced_techniques': 4.0
        }
        
        for analysis_type, weight in weights.items():
            analysis_results = results.get(analysis_type, {})
            
            if isinstance(analysis_results, dict):
                pattern_count = sum(len(patterns) for patterns in analysis_results.values() 
                                 if isinstance(patterns, list))
                total_score += pattern_count * weight
        
        # Classify obfuscation level
        if total_score < 5:
            return "minimal"
        elif total_score < 15:
            return "moderate"
        elif total_score < 30:
            return "high"
        else:
            return "extreme"
    
    def _extract_detected_patterns(self, results: Dict[str, Any]) -> List[ObfuscationPattern]:
        """Extract all detected patterns into standardized format"""
        patterns = []
        
        # Convert analysis results to ObfuscationPattern objects
        for analysis_type, analysis_results in results.items():
            if isinstance(analysis_results, dict):
                for pattern_type, pattern_list in analysis_results.items():
                    if isinstance(pattern_list, list):
                        for pattern_data in pattern_list:
                            if isinstance(pattern_data, dict):
                                pattern = self._convert_to_obfuscation_pattern(
                                    pattern_data, analysis_type, pattern_type
                                )
                                if pattern:
                                    patterns.append(pattern)
        
        return patterns
    
    def _convert_to_obfuscation_pattern(self, pattern_data: Dict[str, Any], 
                                      analysis_type: str, pattern_type: str) -> Optional[ObfuscationPattern]:
        """Convert pattern data to ObfuscationPattern object"""
        try:
            # Map pattern types to enum values
            type_mapping = {
                'control_flow_flattening': ObfuscationType.CONTROL_FLOW_FLATTENING,
                'opaque_predicate': ObfuscationType.OPAQUE_PREDICATES,
                'bogus_control_flow': ObfuscationType.BOGUS_CONTROL_FLOW,
                'instruction_substitution': ObfuscationType.INSTRUCTION_SUBSTITUTION,
                'string_encryption': ObfuscationType.STRING_ENCRYPTION,
                'xor_obfuscation': ObfuscationType.XOR_OBFUSCATION,
                'api_hashing': ObfuscationType.API_HASHING,
                'dynamic_api_loading': ObfuscationType.DYNAMIC_API_LOADING,
                'code_virtualization': ObfuscationType.CODE_VIRTUALIZATION
            }
            
            obfuscation_type = type_mapping.get(pattern_type, ObfuscationType.CUSTOM_ENCODING)
            
            # Determine severity
            confidence = pattern_data.get('confidence', 0.5)
            if confidence >= 0.8:
                severity = ObfuscationSeverity.HIGH
            elif confidence >= 0.6:
                severity = ObfuscationSeverity.MEDIUM
            else:
                severity = ObfuscationSeverity.LOW
            
            # Extract addresses
            addresses = []
            if 'address' in pattern_data:
                addresses = [pattern_data['address']]
            elif 'addresses' in pattern_data:
                addresses = pattern_data['addresses']
            
            # Generate description
            description = self._generate_pattern_description(pattern_data, pattern_type)
            
            # Extract indicators
            indicators = pattern_data.get('indicators', [])
            if 'pattern' in pattern_data:
                indicators.append(pattern_data['pattern'])
            
            return ObfuscationPattern(
                type=obfuscation_type,
                severity=severity,
                confidence=confidence,
                addresses=addresses,
                description=description,
                indicators=indicators,
                metadata=pattern_data,
                detection_method=pattern_data.get('detection_method', 'heuristic')
            )
            
        except Exception as e:
            self.logger.error(f"Failed to convert pattern: {e}")
            return None
    
    def _generate_pattern_description(self, pattern_data: Dict[str, Any], pattern_type: str) -> str:
        """Generate human-readable description for pattern"""
        descriptions = {
            'control_flow_flattening': "Control flow flattening detected - original program structure obscured",
            'opaque_predicate': "Opaque predicate found - conditional branch with predetermined outcome",
            'instruction_substitution': "Instruction substitution detected - simple operations replaced with complex equivalents",
            'string_encryption': "Encrypted strings detected - string data is obfuscated",
            'api_hashing': "API hashing detected - API calls resolved through hash lookups",
            'dynamic_api_loading': "Dynamic API loading detected - APIs resolved at runtime"
        }
        
        base_description = descriptions.get(pattern_type, f"Obfuscation pattern of type {pattern_type} detected")
        
        # Add specific details if available
        if 'type' in pattern_data:
            base_description += f" ({pattern_data['type']})"
        
        return base_description
    
    def _assess_severity(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall severity of obfuscation"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        patterns = self._extract_detected_patterns(results)
        
        for pattern in patterns:
            if pattern.confidence >= 0.9:
                severity_counts['critical'] += 1
            elif pattern.confidence >= 0.7:
                severity_counts['high'] += 1
            elif pattern.confidence >= 0.5:
                severity_counts['medium'] += 1
            else:
                severity_counts['low'] += 1
        
        # Calculate overall risk score
        risk_score = (severity_counts['critical'] * 10 + 
                     severity_counts['high'] * 5 + 
                     severity_counts['medium'] * 2 + 
                     severity_counts['low'] * 1)
        
        return {
            'severity_distribution': severity_counts,
            'risk_score': risk_score,
            'overall_risk_level': self._categorize_risk_level(risk_score)
        }
    
    def _categorize_risk_level(self, risk_score: int) -> str:
        """Categorize risk level based on score"""
        if risk_score >= 50:
            return "critical"
        elif risk_score >= 25:
            return "high"
        elif risk_score >= 10:
            return "medium"
        else:
            return "low"
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate analysis and bypass recommendations"""
        recommendations = []
        
        patterns = self._extract_detected_patterns(results)
        obfuscation_types = {pattern.type for pattern in patterns}
        
        # Generate specific recommendations based on detected patterns
        for obf_type in obfuscation_types:
            if obf_type == ObfuscationType.CONTROL_FLOW_FLATTENING:
                recommendations.append({
                    'type': 'analysis',
                    'priority': 'high',
                    'description': 'Control flow flattening detected. Use specialized deobfuscation tools.',
                    'tools': ['De4dot', 'FLARE-ON tools', 'Manual analysis with IDA Pro']
                })
            
            elif obf_type == ObfuscationType.STRING_ENCRYPTION:
                recommendations.append({
                    'type': 'analysis',
                    'priority': 'medium',
                    'description': 'Encrypted strings found. Analyze decryption routines.',
                    'tools': ['String analysis tools', 'Dynamic analysis', 'Memory dumps']
                })
            
            elif obf_type == ObfuscationType.API_HASHING:
                recommendations.append({
                    'type': 'analysis',
                    'priority': 'high',
                    'description': 'API hashing detected. Resolve hash-to-API mappings.',
                    'tools': ['API hash databases', 'Dynamic API monitoring', 'HashDB lookup']
                })
            
            elif obf_type == ObfuscationType.CODE_VIRTUALIZATION:
                recommendations.append({
                    'type': 'analysis',
                    'priority': 'critical',
                    'description': 'Code virtualization detected. Advanced techniques required.',
                    'tools': ['Specialized VM analysis tools', 'VMProtect unpacker', 'Manual reverse engineering']
                })
        
        # Add general recommendations
        total_patterns = len(patterns)
        if total_patterns > 10:
            recommendations.append({
                'type': 'general',
                'priority': 'high',
                'description': 'Heavy obfuscation detected. Multi-stage analysis recommended.',
                'tools': ['Combined static/dynamic analysis', 'Specialized deobfuscation suite']
            })
        
        return recommendations
    
    def _cleanup_session(self):
        """Clean up analysis session"""
        if self.r2:
            try:
                self.r2.quit()
            except:
                pass
            self.r2 = None
    
    # Helper methods for instruction and address extraction
    def _extract_instructions(self, disasm: str) -> List[str]:
        """Extract instruction opcodes from disassembly"""
        instructions = []
        lines = disasm.split('\n')
        
        for line in lines:
            # Simple regex to extract instruction opcode
            import re
            match = re.search(r'\s+([a-zA-Z]+)', line)
            if match:
                instructions.append(match.group(1).lower())
        
        return instructions
    
    def _extract_address(self, line: str) -> int:
        """Extract address from disassembly line"""
        import re
        match = re.search(r'0x([0-9a-fA-F]+)', line)
        if match:
            return int(match.group(1), 16)
        return 0
    
    def _extract_address_from_sequence(self, disasm: str, line_index: int) -> int:
        """Extract address from sequence at line index"""
        lines = disasm.split('\n')
        if line_index < len(lines):
            return self._extract_address(lines[line_index])
        return 0
    
    def _extract_registers(self, instruction: str) -> List[str]:
        """Extract register names from instruction"""
        import re
        
        # Common x86/x64 registers
        registers = re.findall(r'\b(e?[abcd]x|e?[sb]p|e?[sd]i|r[0-9]+[dwb]?)\b', 
                              instruction.lower())
        return list(set(registers))
    
    def _is_unnecessary_move(self, instruction: str) -> bool:
        """Check if instruction is an unnecessary register move"""
        inst_lower = instruction.lower()
        
        # Look for mov reg, reg (same register)
        import re
        match = re.search(r'mov\s+(\w+),\s*(\w+)', inst_lower)
        if match:
            reg1, reg2 = match.groups()
            return reg1 == reg2
        
        return False
    
    def _find_pattern_variations(self, instructions: List[str]) -> List[Dict[str, Any]]:
        """Find instruction pattern variations"""
        variations = []
        
        # Look for functionally equivalent sequences
        # This is a simplified version - real implementation would be more complex
        
        return variations
    
    def _has_equivalent_sequences(self, sequence: List[str], all_instructions: List[str]) -> bool:
        """Check if sequence has equivalent patterns elsewhere"""
        # Simplified implementation
        sequence_str = ' '.join(sequence)
        all_str = ' '.join(all_instructions)
        
        return all_str.count(sequence_str) > 1
    
    def _is_block_reachable(self, block_addr: int, cfg: Dict[str, Any]) -> bool:
        """Check if a basic block is reachable in CFG"""
        # Simplified reachability check
        # Real implementation would do proper graph traversal
        return True
    
    def _detect_useless_operations(self, block_addr: int) -> List[Dict[str, Any]]:
        """Detect useless operations in a basic block"""
        useless_ops = []
        
        if not self.r2:
            return useless_ops
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        lines = disasm.split('\n')
        
        for line in lines:
            if any(op in line.lower() for op in ['nop', 'int3']):
                useless_ops.append({
                    'address': self._extract_address(line),
                    'instruction': line.strip(),
                    'type': 'useless_operation',
                    'confidence': 0.9
                })
        
        return useless_ops