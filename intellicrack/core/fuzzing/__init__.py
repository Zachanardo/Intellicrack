"""
Intelligent Fuzzing System for Intellicrack

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

from .fuzzing_engine import (
    FuzzingEngine,
    FuzzingConfig,
    FuzzingResult,
    FuzzingStrategy,
    FuzzingTarget,
    ExecutionResult,
    FuzzingStats
)

from .intelligent_mutation_engine import (
    IntelligentMutationEngine,
    MutationStrategy,
    MutationResult,
    BaseMutator,
    RandomMutator,
    BitFlipMutator,
    ArithmeticMutator,
    DictionaryMutator,
    SpliceMutator,
    StructureAwareMutator,
    AIGuidedMutator
)

from .coverage_tracker import (
    CoverageTracker,
    CoverageBackend,
    CoverageType,
    CoverageData,
    CoverageAnalysis
)

from .crash_analyzer import (
    CrashAnalyzer,
    CrashType,
    CrashReport,
    ExploitabilityLevel,
    ExploitabilityAssessment,
    CrashSimilarity
)

from .test_case_generator import (
    TestCaseGenerator,
    GenerationStrategy,
    InputFormat,
    GrammarRule,
    StructureTemplate,
    TestCaseMetadata,
    GeneratedTestCase,
    BaseGenerator,
    RandomGenerator,
    GrammarBasedGenerator,
    StructureAwareGenerator,
    AIGuidedGenerator
)

from .neural_fuzzer import (
    NeuralFuzzer,
    NetworkArchitecture,
    TrainingStrategy,
    TrainingMetrics,
    NeuralGenerationResult,
    FuzzingDataset,
    NeuralNetworkBase,
    FeedforwardGenerator,
    LSTMGenerator,
    VariationalAutoencoder,
    GenerativeAdversarialNetwork
)

from .fuzzing_orchestrator import (
    FuzzingOrchestrator,
    CampaignPhase,
    AgentRole,
    Priority,
    CampaignConfig,
    AgentTask,
    CampaignMetrics,
    CampaignStatus,
    FuzzingAgent
)

from .ai_integration import (
    FuzzingAIIntegrator,
    AIIntegrationMode,
    AICapability,
    AIRecommendation,
    AIAnalysisResult
)

from .safety_framework import (
    SafetyFramework,
    SafetyLevel,
    IsolationType,
    ViolationType,
    SafetyConstraints,
    SafetyViolation,
    IsolationResult,
    ResourceMonitor,
    FileSystemIsolator,
    ProcessIsolator,
    NetworkIsolator
)

__all__ = [
    # Core fuzzing engine
    'FuzzingEngine',
    'FuzzingConfig',
    'FuzzingResult',
    'FuzzingStrategy',
    'FuzzingTarget',
    'ExecutionResult',
    'FuzzingStats',
    
    # Intelligent mutation
    'IntelligentMutationEngine',
    'MutationStrategy',
    'MutationResult',
    'BaseMutator',
    'RandomMutator',
    'BitFlipMutator',
    'ArithmeticMutator',
    'DictionaryMutator',
    'SpliceMutator',
    'StructureAwareMutator',
    'AIGuidedMutator',
    
    # Coverage tracking
    'CoverageTracker',
    'CoverageBackend',
    'CoverageType',
    'CoverageData',
    'CoverageAnalysis',
    
    # Crash analysis
    'CrashAnalyzer',
    'CrashType',
    'CrashReport',
    'ExploitabilityLevel',
    'ExploitabilityAssessment',
    'CrashSimilarity',
    
    # Test case generation
    'TestCaseGenerator',
    'GenerationStrategy',
    'InputFormat',
    'GrammarRule',
    'StructureTemplate',
    'TestCaseMetadata',
    'GeneratedTestCase',
    'BaseGenerator',
    'RandomGenerator',
    'GrammarBasedGenerator',
    'StructureAwareGenerator',
    'AIGuidedGenerator',
    
    # Neural fuzzing
    'NeuralFuzzer',
    'NetworkArchitecture',
    'TrainingStrategy',
    'TrainingMetrics',
    'NeuralGenerationResult',
    'FuzzingDataset',
    'NeuralNetworkBase',
    'FeedforwardGenerator',
    'LSTMGenerator',
    'VariationalAutoencoder',
    'GenerativeAdversarialNetwork',
    
    # Orchestration
    'FuzzingOrchestrator',
    'CampaignPhase',
    'AgentRole',
    'Priority',
    'CampaignConfig',
    'AgentTask',
    'CampaignMetrics',
    'CampaignStatus',
    'FuzzingAgent',
    
    # AI Integration
    'FuzzingAIIntegrator',
    'AIIntegrationMode',
    'AICapability',
    'AIRecommendation',
    'AIAnalysisResult',
    
    # Safety Framework
    'SafetyFramework',
    'SafetyLevel',
    'IsolationType',
    'ViolationType',
    'SafetyConstraints',
    'SafetyViolation',
    'IsolationResult',
    'ResourceMonitor',
    'FileSystemIsolator',
    'ProcessIsolator',
    'NetworkIsolator'
]