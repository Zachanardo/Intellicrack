"""
Multi-Model Consensus Engine

Coordinates multiple LLM models to provide consensus-based analysis and script generation
with weighted voting, confidence scoring, and conflict resolution.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.analysis.unified_model.model import (
    AnalysisSource,
    ConfidenceLevel,
    ProtectionInfo,
    UnifiedBinaryModel
)
from ..utils.logger import get_logger
from .llm_backends import LLMConfig, LLMManager, LLMMessage, LLMProvider, get_llm_manager

logger = get_logger(__name__)


class ConsensusMode(Enum):
    """Consensus determination modes"""
    MAJORITY_VOTE = "majority_vote"
    WEIGHTED_AVERAGE = "weighted_average"
    CONFIDENCE_THRESHOLD = "confidence_threshold"
    EXPERT_PRIORITY = "expert_priority"
    UNANIMOUS = "unanimous"


class ModelExpertise(Enum):
    """Model expertise domains"""
    GENERAL = "general"
    CRYPTOGRAPHY = "cryptography"
    NETWORK_PROTOCOLS = "network_protocols"
    ANTI_DEBUGGING = "anti_debugging"
    VM_DETECTION = "vm_detection"
    LICENSE_SYSTEMS = "license_systems"
    MALWARE_ANALYSIS = "malware_analysis"
    REVERSE_ENGINEERING = "reverse_engineering"


@dataclass
class ModelProfile:
    """Profile for an LLM model with expertise and performance characteristics"""
    model_id: str
    provider: LLMProvider
    expertise_domains: Set[ModelExpertise] = field(default_factory=set)
    confidence_weight: float = 1.0  # Weight for consensus voting
    response_time_avg: float = 0.0  # Average response time in seconds
    success_rate: float = 1.0  # Historical success rate
    max_context_length: int = 4096
    supports_tools: bool = False
    cost_per_token: float = 0.0  # Cost consideration for optimization
    
    # Performance metrics
    total_queries: int = 0
    successful_queries: int = 0
    total_response_time: float = 0.0
    
    def update_metrics(self, success: bool, response_time: float):
        """Update performance metrics after a query"""
        self.total_queries += 1
        if success:
            self.successful_queries += 1
        self.total_response_time += response_time
        
        # Update rolling averages
        self.response_time_avg = self.total_response_time / self.total_queries
        self.success_rate = self.successful_queries / self.total_queries if self.total_queries > 0 else 1.0
        
        # Adjust confidence weight based on performance
        self.confidence_weight = min(2.0, self.success_rate * 1.5)


@dataclass
class ConsensusQuery:
    """Query to be processed by multiple models"""
    query_id: str
    prompt: str
    query_type: str  # "script_generation", "protection_analysis", "bypass_strategy"
    context_data: Dict[str, Any] = field(default_factory=dict)
    required_expertise: Set[ModelExpertise] = field(default_factory=set)
    minimum_models: int = 3
    consensus_mode: ConsensusMode = ConsensusMode.WEIGHTED_AVERAGE
    timeout: float = 60.0
    priority: int = 0


@dataclass
class ModelResponse:
    """Response from a single model"""
    model_id: str
    content: str
    confidence: float  # 0.0 to 1.0
    response_time: float
    tokens_used: int = 0
    has_error: bool = False
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConsensusResult:
    """Result of consensus analysis"""
    query_id: str
    consensus_content: str
    consensus_confidence: float
    individual_responses: List[ModelResponse]
    agreement_score: float  # 0.0 to 1.0 indicating level of agreement
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    processing_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class MultiModelConsensusEngine:
    """Coordinates multiple LLM models for consensus-based analysis"""
    
    def __init__(self):
        self.llm_manager = get_llm_manager()
        self.model_profiles: Dict[str, ModelProfile] = {}
        self.active_queries: Dict[str, ConsensusQuery] = {}
        self.query_results: Dict[str, ConsensusResult] = {}
        self._initialize_default_models()
        
    def _initialize_default_models(self):
        """Initialize default model profiles"""
        # OpenAI GPT-4 - General purpose with good reasoning
        self.register_model_profile(ModelProfile(
            model_id="gpt4-general",
            provider=LLMProvider.OPENAI,
            expertise_domains={ModelExpertise.GENERAL, ModelExpertise.REVERSE_ENGINEERING},
            confidence_weight=1.5,
            max_context_length=8192,
            supports_tools=True,
            cost_per_token=0.00003
        ))
        
        # Claude 3 - Strong at code analysis and security
        self.register_model_profile(ModelProfile(
            model_id="claude3-security",
            provider=LLMProvider.ANTHROPIC,
            expertise_domains={ModelExpertise.CRYPTOGRAPHY, ModelExpertise.LICENSE_SYSTEMS, 
                              ModelExpertise.ANTI_DEBUGGING},
            confidence_weight=1.8,
            max_context_length=100000,
            supports_tools=True,
            cost_per_token=0.00002
        ))
        
        # Local LLaMA model - Privacy-focused analysis
        self.register_model_profile(ModelProfile(
            model_id="llama-local",
            provider=LLMProvider.LLAMACPP,
            expertise_domains={ModelExpertise.MALWARE_ANALYSIS, ModelExpertise.VM_DETECTION},
            confidence_weight=1.2,
            max_context_length=4096,
            supports_tools=False,
            cost_per_token=0.0
        ))
        
        # Ollama Mistral - Fast inference for quick analysis
        self.register_model_profile(ModelProfile(
            model_id="mistral-fast",
            provider=LLMProvider.OLLAMA,
            expertise_domains={ModelExpertise.NETWORK_PROTOCOLS, ModelExpertise.GENERAL},
            confidence_weight=1.0,
            max_context_length=8192,
            supports_tools=False,
            cost_per_token=0.0
        ))
    
    def register_model_profile(self, profile: ModelProfile):
        """Register a model profile for consensus participation"""
        self.model_profiles[profile.model_id] = profile
        logger.info(f"Registered model profile: {profile.model_id} with expertise: {profile.expertise_domains}")
    
    def select_models_for_query(self, query: ConsensusQuery) -> List[ModelProfile]:
        """Select appropriate models based on query requirements"""
        selected_models = []
        
        # First, prioritize models with required expertise
        for model_id, profile in self.model_profiles.items():
            if query.required_expertise and profile.expertise_domains.intersection(query.required_expertise):
                selected_models.append(profile)
        
        # If not enough models, add general-purpose models
        if len(selected_models) < query.minimum_models:
            general_models = [p for p in self.model_profiles.values() 
                            if ModelExpertise.GENERAL in p.expertise_domains 
                            and p not in selected_models]
            selected_models.extend(general_models[:query.minimum_models - len(selected_models)])
        
        # If still not enough, add any available models
        if len(selected_models) < query.minimum_models:
            remaining_models = [p for p in self.model_profiles.values() 
                              if p not in selected_models]
            selected_models.extend(remaining_models[:query.minimum_models - len(selected_models)])
        
        # Sort by confidence weight for prioritization
        selected_models.sort(key=lambda x: x.confidence_weight, reverse=True)
        
        logger.info(f"Selected {len(selected_models)} models for query {query.query_id}")
        return selected_models
    
    async def query_model_async(self, model_profile: ModelProfile, query: ConsensusQuery) -> ModelResponse:
        """Query a single model asynchronously"""
        start_time = time.time()
        
        try:
            # Prepare system prompt based on query type
            system_prompt = self._prepare_system_prompt(query, model_profile)
            
            # Create messages
            messages = [
                LLMMessage(role="system", content=system_prompt),
                LLMMessage(role="user", content=query.prompt)
            ]
            
            # Add context if provided
            if query.context_data:
                context_msg = f"\nContext Information:\n{json.dumps(query.context_data, indent=2)}"
                messages.append(LLMMessage(role="user", content=context_msg))
            
            # Query the model
            response = await asyncio.to_thread(
                self.llm_manager.chat,
                messages,
                llm_id=model_profile.model_id
            )
            
            if response and response.content:
                response_time = time.time() - start_time
                
                # Extract confidence from response if present
                confidence = self._extract_confidence_from_response(response.content)
                
                model_response = ModelResponse(
                    model_id=model_profile.model_id,
                    content=response.content,
                    confidence=confidence,
                    response_time=response_time,
                    tokens_used=response.usage.get("total_tokens", 0) if response.usage else 0
                )
                
                # Update model metrics
                model_profile.update_metrics(True, response_time)
                
                return model_response
            else:
                raise ValueError("Empty response from model")
                
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Error querying model {model_profile.model_id}: {e}")
            
            # Update model metrics
            model_profile.update_metrics(False, response_time)
            
            return ModelResponse(
                model_id=model_profile.model_id,
                content="",
                confidence=0.0,
                response_time=response_time,
                has_error=True,
                error_message=str(e)
            )
    
    def _prepare_system_prompt(self, query: ConsensusQuery, model_profile: ModelProfile) -> str:
        """Prepare system prompt based on query type and model expertise"""
        base_prompt = f"""You are an expert in {', '.join(str(e.value) for e in model_profile.expertise_domains)}.
You are part of a multi-model consensus system for binary analysis and security research.

CRITICAL REQUIREMENTS:
- Provide detailed, accurate analysis based on your expertise
- Include a confidence score (0.0-1.0) in your response
- Focus on actionable insights and concrete recommendations
- NO placeholders or incomplete analysis
- All code and scripts must be production-ready

Query Type: {query.query_type}
"""
        
        # Add query-type specific instructions
        if query.query_type == "script_generation":
            base_prompt += """
Generate complete, functional scripts for the requested purpose.
Include error handling and validation.
Provide scripts that are immediately executable.
"""
        elif query.query_type == "protection_analysis":
            base_prompt += """
Analyze the protection mechanisms in detail.
Identify specific implementations and weaknesses.
Provide concrete bypass strategies where applicable.
"""
        elif query.query_type == "bypass_strategy":
            base_prompt += """
Create detailed bypass strategies for identified protections.
Include step-by-step implementation guidance.
Consider multiple approaches and their trade-offs.
"""
        
        return base_prompt
    
    def _extract_confidence_from_response(self, response: str) -> float:
        """Extract confidence score from model response"""
        import re
        
        # Look for confidence patterns
        patterns = [
            r"confidence:\s*([0-9.]+)",
            r"confidence score:\s*([0-9.]+)",
            r"confidence level:\s*([0-9.]+)",
            r"\[confidence:\s*([0-9.]+)\]",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.lower())
            if match:
                try:
                    confidence = float(match.group(1))
                    return min(1.0, max(0.0, confidence))
                except ValueError:
                    pass
        
        # Default confidence based on response characteristics
        if len(response) > 1000 and "error" not in response.lower():
            return 0.7
        elif len(response) > 500:
            return 0.5
        else:
            return 0.3
    
    async def process_consensus_query(self, query: ConsensusQuery) -> ConsensusResult:
        """Process a query through multiple models and build consensus"""
        start_time = time.time()
        
        # Store active query
        self.active_queries[query.query_id] = query
        
        # Select models for this query
        selected_models = self.select_models_for_query(query)
        
        if not selected_models:
            logger.error(f"No models available for query {query.query_id}")
            return ConsensusResult(
                query_id=query.query_id,
                consensus_content="No models available for consensus",
                consensus_confidence=0.0,
                individual_responses=[],
                agreement_score=0.0,
                processing_time=time.time() - start_time
            )
        
        # Query all selected models concurrently
        tasks = [self.query_model_async(model, query) for model in selected_models]
        responses = await asyncio.gather(*tasks)
        
        # Filter out error responses
        valid_responses = [r for r in responses if not r.has_error and r.content]
        
        if not valid_responses:
            logger.error(f"No valid responses for query {query.query_id}")
            return ConsensusResult(
                query_id=query.query_id,
                consensus_content="All models failed to provide valid responses",
                consensus_confidence=0.0,
                individual_responses=responses,
                agreement_score=0.0,
                processing_time=time.time() - start_time
            )
        
        # Build consensus based on mode
        consensus_result = self._build_consensus(
            query,
            valid_responses,
            selected_models
        )
        
        # Add metadata
        consensus_result.processing_time = time.time() - start_time
        consensus_result.metadata = {
            "models_queried": len(selected_models),
            "valid_responses": len(valid_responses),
            "consensus_mode": query.consensus_mode.value
        }
        
        # Store result
        self.query_results[query.query_id] = consensus_result
        
        # Clean up active query
        del self.active_queries[query.query_id]
        
        return consensus_result
    
    def _build_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                        models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus from model responses based on consensus mode"""
        
        if query.consensus_mode == ConsensusMode.MAJORITY_VOTE:
            return self._majority_vote_consensus(query, responses, models)
        elif query.consensus_mode == ConsensusMode.WEIGHTED_AVERAGE:
            return self._weighted_average_consensus(query, responses, models)
        elif query.consensus_mode == ConsensusMode.CONFIDENCE_THRESHOLD:
            return self._confidence_threshold_consensus(query, responses, models)
        elif query.consensus_mode == ConsensusMode.EXPERT_PRIORITY:
            return self._expert_priority_consensus(query, responses, models)
        elif query.consensus_mode == ConsensusMode.UNANIMOUS:
            return self._unanimous_consensus(query, responses, models)
        else:
            # Default to weighted average
            return self._weighted_average_consensus(query, responses, models)
    
    def _weighted_average_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                                   models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus using weighted average of responses"""
        
        # Create model lookup
        model_lookup = {m.model_id: m for m in models}
        
        # Calculate total weight
        total_weight = sum(
            model_lookup[r.model_id].confidence_weight * r.confidence 
            for r in responses
        )
        
        # Aggregate responses with weights
        if query.query_type == "script_generation":
            # For scripts, select the highest weighted response
            best_response = max(
                responses,
                key=lambda r: model_lookup[r.model_id].confidence_weight * r.confidence
            )
            consensus_content = best_response.content
            
            # Include alternatives in metadata
            alternatives = [
                {
                    "model_id": r.model_id,
                    "weight": model_lookup[r.model_id].confidence_weight * r.confidence,
                    "preview": r.content[:200] + "..." if len(r.content) > 200 else r.content
                }
                for r in responses if r != best_response
            ]
            
        else:
            # For analysis, combine insights from all models
            insights = []
            for response in responses:
                weight = model_lookup[response.model_id].confidence_weight * response.confidence
                weight_pct = (weight / total_weight) * 100 if total_weight > 0 else 0
                insights.append(f"[{response.model_id} - Weight: {weight_pct:.1f}%]:\n{response.content}\n")
            
            consensus_content = "\n=== CONSENSUS ANALYSIS ===\n" + "\n".join(insights)
        
        # Calculate consensus confidence
        consensus_confidence = sum(
            (model_lookup[r.model_id].confidence_weight * r.confidence / total_weight) * r.confidence
            for r in responses
        ) if total_weight > 0 else 0.0
        
        # Calculate agreement score based on response similarity
        agreement_score = self._calculate_agreement_score(responses)
        
        # Identify conflicts
        conflicts = self._identify_conflicts(responses)
        
        return ConsensusResult(
            query_id=query.query_id,
            consensus_content=consensus_content,
            consensus_confidence=consensus_confidence,
            individual_responses=responses,
            agreement_score=agreement_score,
            conflicts=conflicts
        )
    
    def _calculate_agreement_score(self, responses: List[ModelResponse]) -> float:
        """Calculate agreement score between responses"""
        if len(responses) < 2:
            return 1.0
        
        # Simple approach: compare response lengths and key terms
        lengths = [len(r.content) for r in responses]
        avg_length = sum(lengths) / len(lengths)
        
        # Calculate length variance
        length_variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths)
        length_agreement = 1.0 / (1.0 + length_variance / (avg_length ** 2))
        
        # Extract key terms from each response
        key_terms_sets = []
        for response in responses:
            # Simple keyword extraction
            words = response.content.lower().split()
            key_terms = set(w for w in words if len(w) > 5 and w.isalnum())
            key_terms_sets.append(key_terms)
        
        # Calculate Jaccard similarity between term sets
        if len(key_terms_sets) > 1:
            similarities = []
            for i in range(len(key_terms_sets)):
                for j in range(i + 1, len(key_terms_sets)):
                    intersection = len(key_terms_sets[i].intersection(key_terms_sets[j]))
                    union = len(key_terms_sets[i].union(key_terms_sets[j]))
                    if union > 0:
                        similarities.append(intersection / union)
            
            term_agreement = sum(similarities) / len(similarities) if similarities else 0.0
        else:
            term_agreement = 1.0
        
        # Combine length and term agreement
        return (length_agreement + term_agreement) / 2.0
    
    def _identify_conflicts(self, responses: List[ModelResponse]) -> List[Dict[str, Any]]:
        """Identify conflicts between model responses"""
        conflicts = []
        
        # Look for contradictory statements
        for i, resp1 in enumerate(responses):
            for j, resp2 in enumerate(responses[i+1:], i+1):
                # Simple conflict detection based on negation patterns
                if ("not" in resp1.content.lower() and "not" not in resp2.content.lower()) or \
                   ("not" in resp2.content.lower() and "not" not in resp1.content.lower()):
                    conflicts.append({
                        "type": "contradiction",
                        "models": [resp1.model_id, resp2.model_id],
                        "description": "Potential contradictory statements detected"
                    })
                
                # Check for significantly different confidence levels
                if abs(resp1.confidence - resp2.confidence) > 0.5:
                    conflicts.append({
                        "type": "confidence_mismatch",
                        "models": [resp1.model_id, resp2.model_id],
                        "description": f"Large confidence gap: {resp1.confidence:.2f} vs {resp2.confidence:.2f}"
                    })
        
        return conflicts
    
    def _majority_vote_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                                models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus using majority vote"""
        # For simplicity, use the most common response pattern
        # In practice, this would involve more sophisticated clustering
        
        # Group similar responses
        response_groups = []
        for response in responses:
            # Find similar group
            found_group = False
            for group in response_groups:
                if self._responses_similar(response, group[0]):
                    group.append(response)
                    found_group = True
                    break
            
            if not found_group:
                response_groups.append([response])
        
        # Find majority group
        majority_group = max(response_groups, key=len)
        
        # Use best response from majority group
        best_response = max(majority_group, key=lambda r: r.confidence)
        
        consensus_confidence = len(majority_group) / len(responses)
        agreement_score = len(majority_group) / len(responses)
        
        return ConsensusResult(
            query_id=query.query_id,
            consensus_content=best_response.content,
            consensus_confidence=consensus_confidence,
            individual_responses=responses,
            agreement_score=agreement_score,
            conflicts=[]
        )
    
    def _responses_similar(self, resp1: ModelResponse, resp2: ModelResponse) -> bool:
        """Check if two responses are similar"""
        # Simple similarity check based on length and key terms
        length_ratio = len(resp1.content) / len(resp2.content) if len(resp2.content) > 0 else 0
        
        if 0.8 <= length_ratio <= 1.2:
            # Extract key terms
            terms1 = set(resp1.content.lower().split())
            terms2 = set(resp2.content.lower().split())
            
            # Jaccard similarity
            intersection = len(terms1.intersection(terms2))
            union = len(terms1.union(terms2))
            
            return (intersection / union) > 0.6 if union > 0 else False
        
        return False
    
    def _confidence_threshold_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                                       models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus using confidence threshold"""
        threshold = 0.7  # Default threshold
        
        # Filter responses above threshold
        high_confidence_responses = [r for r in responses if r.confidence >= threshold]
        
        if not high_confidence_responses:
            # Lower threshold and try again
            threshold = 0.5
            high_confidence_responses = [r for r in responses if r.confidence >= threshold]
        
        if high_confidence_responses:
            # Use weighted average of high confidence responses
            return self._weighted_average_consensus(query, high_confidence_responses, models)
        else:
            # Fall back to all responses
            return self._weighted_average_consensus(query, responses, models)
    
    def _expert_priority_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                                  models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus prioritizing domain experts"""
        model_lookup = {m.model_id: m for m in models}
        
        # Sort responses by expertise match
        def expertise_score(response: ModelResponse) -> float:
            model = model_lookup[response.model_id]
            if query.required_expertise:
                match_count = len(model.expertise_domains.intersection(query.required_expertise))
                return match_count * response.confidence
            return response.confidence
        
        sorted_responses = sorted(responses, key=expertise_score, reverse=True)
        
        # Use top expert response as primary
        expert_response = sorted_responses[0]
        
        # Include other expert opinions
        other_experts = []
        for resp in sorted_responses[1:3]:  # Top 3 experts
            if expertise_score(resp) > 0:
                other_experts.append(f"[{resp.model_id}]: {resp.content[:200]}...")
        
        consensus_content = f"PRIMARY EXPERT ANALYSIS [{expert_response.model_id}]:\n{expert_response.content}"
        
        if other_experts:
            consensus_content += "\n\nADDITIONAL EXPERT OPINIONS:\n" + "\n".join(other_experts)
        
        return ConsensusResult(
            query_id=query.query_id,
            consensus_content=consensus_content,
            consensus_confidence=expert_response.confidence,
            individual_responses=responses,
            agreement_score=self._calculate_agreement_score(responses),
            conflicts=self._identify_conflicts(responses)
        )
    
    def _unanimous_consensus(self, query: ConsensusQuery, responses: List[ModelResponse], 
                            models: List[ModelProfile]) -> ConsensusResult:
        """Build consensus requiring unanimous agreement"""
        
        # Check if all responses are similar
        if len(responses) < 2:
            return self._weighted_average_consensus(query, responses, models)
        
        all_similar = True
        base_response = responses[0]
        
        for response in responses[1:]:
            if not self._responses_similar(base_response, response):
                all_similar = False
                break
        
        if all_similar:
            # Full agreement - use highest confidence response
            best_response = max(responses, key=lambda r: r.confidence)
            
            return ConsensusResult(
                query_id=query.query_id,
                consensus_content=best_response.content,
                consensus_confidence=1.0,  # Full agreement
                individual_responses=responses,
                agreement_score=1.0,
                conflicts=[]
            )
        else:
            # No unanimous agreement - report disagreement
            consensus_content = "NO UNANIMOUS CONSENSUS REACHED\n\n"
            consensus_content += "Individual model responses:\n"
            
            for response in responses:
                consensus_content += f"\n[{response.model_id}]:\n{response.content}\n"
            
            return ConsensusResult(
                query_id=query.query_id,
                consensus_content=consensus_content,
                consensus_confidence=0.3,  # Low confidence due to disagreement
                individual_responses=responses,
                agreement_score=self._calculate_agreement_score(responses),
                conflicts=self._identify_conflicts(responses)
            )
    
    def generate_script_with_consensus(self, prompt: str, script_type: str, 
                                     context_data: Dict[str, Any] = None,
                                     required_expertise: Set[ModelExpertise] = None) -> ConsensusResult:
        """Generate script using multi-model consensus"""
        query = ConsensusQuery(
            query_id=f"script_{script_type}_{int(time.time())}",
            prompt=prompt,
            query_type="script_generation",
            context_data=context_data or {},
            required_expertise=required_expertise or {ModelExpertise.REVERSE_ENGINEERING},
            minimum_models=3,
            consensus_mode=ConsensusMode.EXPERT_PRIORITY
        )
        
        # Run async consensus query
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.process_consensus_query(query))
            return result
        finally:
            loop.close()
    
    def analyze_protection_with_consensus(self, binary_data: Dict[str, Any],
                                        unified_model: Optional['UnifiedBinaryModel'] = None) -> ConsensusResult:
        """Analyze protection mechanisms using multi-model consensus"""
        # Prepare context with binary information
        context_data = {
            "binary_data": binary_data,
            "file_format": unified_model.metadata.file_format if unified_model else "unknown",
            "architecture": unified_model.metadata.architecture if unified_model else "unknown",
            "detected_protections": [p.name for p in unified_model.protection_analysis.protections.values()] if unified_model else []
        }
        
        prompt = f"""Analyze the following binary for protection mechanisms:

Binary Information:
- Format: {context_data['file_format']}
- Architecture: {context_data['architecture']}
- Size: {binary_data.get('size', 'unknown')}

Please identify:
1. License verification mechanisms
2. Anti-debugging techniques
3. VM/sandbox detection
4. Cryptographic protections
5. Code obfuscation methods

Provide detailed analysis with confidence scores."""

        query = ConsensusQuery(
            query_id=f"protection_analysis_{int(time.time())}",
            prompt=prompt,
            query_type="protection_analysis",
            context_data=context_data,
            required_expertise={
                ModelExpertise.LICENSE_SYSTEMS,
                ModelExpertise.ANTI_DEBUGGING,
                ModelExpertise.VM_DETECTION,
                ModelExpertise.CRYPTOGRAPHY
            },
            minimum_models=4,
            consensus_mode=ConsensusMode.WEIGHTED_AVERAGE
        )
        
        # Run async consensus query
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.process_consensus_query(query))
            return result
        finally:
            loop.close()
    
    def create_bypass_strategy_with_consensus(self, protection_info: ProtectionInfo,
                                            binary_context: Dict[str, Any]) -> ConsensusResult:
        """Create bypass strategy using multi-model consensus"""
        prompt = f"""Create a detailed bypass strategy for the following protection:

Protection: {protection_info.name}
Type: {protection_info.type}
Version: {protection_info.version or 'unknown'}
Characteristics:
- VM Protection: {protection_info.is_vm_protection}
- Encryption: {protection_info.is_encryption}
- Anti-Debug: {protection_info.is_anti_debug}
- Anti-VM: {protection_info.is_anti_vm}

Binary Context:
{json.dumps(binary_context, indent=2)}

Provide:
1. Step-by-step bypass methodology
2. Required tools and techniques
3. Potential challenges and solutions
4. Alternative approaches
5. Success probability assessment"""

        query = ConsensusQuery(
            query_id=f"bypass_strategy_{protection_info.name}_{int(time.time())}",
            prompt=prompt,
            query_type="bypass_strategy",
            context_data={
                "protection": protection_info.__dict__,
                "binary_context": binary_context
            },
            required_expertise={
                ModelExpertise.REVERSE_ENGINEERING,
                ModelExpertise.ANTI_DEBUGGING,
                ModelExpertise.VM_DETECTION
            },
            minimum_models=3,
            consensus_mode=ConsensusMode.EXPERT_PRIORITY,
            timeout=90.0
        )
        
        # Run async consensus query
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(self.process_consensus_query(query))
            return result
        finally:
            loop.close()
    
    def get_model_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for all models"""
        stats = {}
        
        for model_id, profile in self.model_profiles.items():
            stats[model_id] = {
                "total_queries": profile.total_queries,
                "success_rate": profile.success_rate,
                "avg_response_time": profile.response_time_avg,
                "confidence_weight": profile.confidence_weight,
                "expertise_domains": [e.value for e in profile.expertise_domains],
                "cost_per_token": profile.cost_per_token
            }
        
        return stats
    
    def optimize_model_selection(self, performance_threshold: float = 0.8):
        """Optimize model selection based on performance metrics"""
        for model_id, profile in self.model_profiles.items():
            if profile.total_queries > 10:  # Need sufficient data
                if profile.success_rate < performance_threshold:
                    # Reduce confidence weight for underperforming models
                    profile.confidence_weight *= 0.8
                    logger.warning(f"Reduced confidence weight for {model_id} due to low success rate")
                elif profile.success_rate > 0.95:
                    # Increase confidence weight for high performers
                    profile.confidence_weight = min(2.0, profile.confidence_weight * 1.1)
                    logger.info(f"Increased confidence weight for {model_id} due to high success rate")