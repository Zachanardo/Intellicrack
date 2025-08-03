"""
AI Feedback Loop System

Implements continuous learning from script execution results, maintaining a knowledge
base of successful patterns and improving future script generation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.analysis.unified_model.model import ProtectionInfo, UnifiedBinaryModel
from ..utils.logger import get_logger
from .ai_script_generator import GeneratedScript, ProtectionType, ScriptType
from .consensus_engine import ConsensusResult, ModelExpertise, MultiModelConsensusEngine

logger = get_logger(__name__)


class ExecutionStatus(Enum):
    """Script execution status"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"  # Blocked by protection


class FeedbackType(Enum):
    """Types of feedback"""
    EXECUTION_RESULT = "execution_result"
    USER_RATING = "user_rating"
    PERFORMANCE_METRIC = "performance_metric"
    ERROR_ANALYSIS = "error_analysis"
    SUCCESS_PATTERN = "success_pattern"
    FAILURE_PATTERN = "failure_pattern"


@dataclass
class ScriptExecutionResult:
    """Result from script execution"""
    script_id: str
    script_type: ScriptType
    target_protection: Optional[ProtectionType]
    execution_status: ExecutionStatus
    execution_time: float
    
    # Detailed results
    output: str = ""
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Success metrics
    protection_bypassed: bool = False
    functions_hooked: int = 0
    memory_patches_applied: int = 0
    api_calls_intercepted: int = 0
    
    # Performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    
    # Context
    binary_hash: Optional[str] = None
    architecture: Optional[str] = None
    protection_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "script_id": self.script_id,
            "script_type": self.script_type.value,
            "target_protection": self.target_protection.value if self.target_protection else None,
            "execution_status": self.execution_status.value,
            "execution_time": self.execution_time,
            "output": self.output[:1000],  # Truncate long output
            "errors": self.errors,
            "warnings": self.warnings,
            "protection_bypassed": self.protection_bypassed,
            "functions_hooked": self.functions_hooked,
            "memory_patches_applied": self.memory_patches_applied,
            "api_calls_intercepted": self.api_calls_intercepted,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "binary_hash": self.binary_hash,
            "architecture": self.architecture,
            "protection_details": self.protection_details
        }


@dataclass
class FeedbackEntry:
    """Single feedback entry"""
    feedback_id: str
    timestamp: datetime
    feedback_type: FeedbackType
    script_id: str
    
    # Feedback content
    rating: Optional[float] = None  # 0.0 to 1.0
    comments: Optional[str] = None
    execution_result: Optional[ScriptExecutionResult] = None
    
    # Patterns identified
    success_patterns: List[str] = field(default_factory=list)
    failure_patterns: List[str] = field(default_factory=list)
    
    # Recommendations
    improvements: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "feedback_id": self.feedback_id,
            "timestamp": self.timestamp.isoformat(),
            "feedback_type": self.feedback_type.value,
            "script_id": self.script_id,
            "rating": self.rating,
            "comments": self.comments,
            "execution_result": self.execution_result.to_dict() if self.execution_result else None,
            "success_patterns": self.success_patterns,
            "failure_patterns": self.failure_patterns,
            "improvements": self.improvements
        }


@dataclass
class PatternKnowledge:
    """Knowledge about successful/failed patterns"""
    pattern_id: str
    pattern_type: str  # "success" or "failure"
    pattern_description: str
    
    # Pattern details
    script_type: ScriptType
    protection_type: Optional[ProtectionType]
    architecture: Optional[str]
    
    # Pattern content
    code_snippet: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Statistics
    occurrence_count: int = 0
    success_rate: float = 0.0
    last_seen: Optional[datetime] = None
    
    # AI insights
    ai_analysis: Optional[str] = None
    recommended_alternatives: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "pattern_description": self.pattern_description,
            "script_type": self.script_type.value,
            "protection_type": self.protection_type.value if self.protection_type else None,
            "architecture": self.architecture,
            "code_snippet": self.code_snippet,
            "context": self.context,
            "occurrence_count": self.occurrence_count,
            "success_rate": self.success_rate,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "ai_analysis": self.ai_analysis,
            "recommended_alternatives": self.recommended_alternatives
        }


class FeedbackLoopEngine:
    """Manages AI feedback loop for continuous improvement"""
    
    def __init__(self, db_path: Optional[str] = None):
        self.consensus_engine = MultiModelConsensusEngine()
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), 
            "feedback_knowledge.db"
        )
        self._init_database()
        self._pattern_cache: Dict[str, PatternKnowledge] = {}
        self._feedback_buffer: List[FeedbackEntry] = []
        
    def _init_database(self):
        """Initialize feedback database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback_entries (
                feedback_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                feedback_type TEXT NOT NULL,
                script_id TEXT NOT NULL,
                rating REAL,
                comments TEXT,
                execution_result TEXT,
                success_patterns TEXT,
                failure_patterns TEXT,
                improvements TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pattern_knowledge (
                pattern_id TEXT PRIMARY KEY,
                pattern_type TEXT NOT NULL,
                pattern_description TEXT NOT NULL,
                script_type TEXT NOT NULL,
                protection_type TEXT,
                architecture TEXT,
                code_snippet TEXT NOT NULL,
                context TEXT,
                occurrence_count INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                last_seen TEXT,
                ai_analysis TEXT,
                recommended_alternatives TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS script_performance (
                script_id TEXT PRIMARY KEY,
                script_type TEXT NOT NULL,
                target_protection TEXT,
                total_executions INTEGER DEFAULT 0,
                successful_executions INTEGER DEFAULT 0,
                average_execution_time REAL DEFAULT 0.0,
                last_execution TEXT,
                overall_rating REAL DEFAULT 0.0
            )
        ''')
        
        # Create indices
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_feedback_script ON feedback_entries(script_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pattern_type ON pattern_knowledge(pattern_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_script_performance ON script_performance(script_type, target_protection)')
        
        conn.commit()
        conn.close()
    
    def record_execution_result(self, script: GeneratedScript, result: ScriptExecutionResult) -> FeedbackEntry:
        """Record script execution result"""
        
        feedback = FeedbackEntry(
            feedback_id=f"exec_{script.script_type.value}_{int(time.time())}",
            timestamp=datetime.now(),
            feedback_type=FeedbackType.EXECUTION_RESULT,
            script_id=script.metadata.get("script_id", "unknown"),
            execution_result=result
        )
        
        # Analyze patterns
        if result.execution_status == ExecutionStatus.SUCCESS:
            feedback.success_patterns = self._extract_success_patterns(script, result)
        else:
            feedback.failure_patterns = self._extract_failure_patterns(script, result)
        
        # Generate improvements
        feedback.improvements = self._generate_improvements(script, result)
        
        # Store feedback
        self._store_feedback(feedback)
        
        # Update pattern knowledge
        self._update_pattern_knowledge(feedback)
        
        # Update script performance metrics
        self._update_script_performance(script, result)
        
        return feedback
    
    def _extract_success_patterns(self, script: GeneratedScript, result: ScriptExecutionResult) -> List[str]:
        """Extract successful patterns from execution"""
        patterns = []
        
        # Analyze what worked
        if result.protection_bypassed:
            patterns.append(f"successful_{result.target_protection.value}_bypass")
        
        if result.functions_hooked > 0:
            patterns.append(f"hooked_{result.functions_hooked}_functions")
        
        if result.memory_patches_applied > 0:
            patterns.append(f"applied_{result.memory_patches_applied}_patches")
        
        # Extract code patterns that worked
        successful_constructs = self._analyze_successful_code(script.content, result)
        patterns.extend(successful_constructs)
        
        return patterns
    
    def _extract_failure_patterns(self, script: GeneratedScript, result: ScriptExecutionResult) -> List[str]:
        """Extract failure patterns from execution"""
        patterns = []
        
        # Analyze errors
        for error in result.errors:
            if "permission" in error.lower():
                patterns.append("permission_denied")
            elif "not found" in error.lower():
                patterns.append("target_not_found")
            elif "timeout" in error.lower():
                patterns.append("execution_timeout")
            elif "detected" in error.lower():
                patterns.append("anti_analysis_detected")
        
        # Extract problematic code patterns
        problematic_constructs = self._analyze_problematic_code(script.content, result)
        patterns.extend(problematic_constructs)
        
        return patterns
    
    def _analyze_successful_code(self, script_content: str, result: ScriptExecutionResult) -> List[str]:
        """Analyze code to identify successful patterns"""
        patterns = []
        
        # Look for specific successful constructs
        if "Interceptor.attach" in script_content and result.functions_hooked > 0:
            patterns.append("interceptor_attach_success")
        
        if "Memory.write" in script_content and result.memory_patches_applied > 0:
            patterns.append("memory_write_success")
        
        if "Process.enumerateModules" in script_content and "module" in result.output.lower():
            patterns.append("module_enumeration_success")
        
        # Architecture-specific successes
        if result.architecture:
            if "x64" in result.architecture and "context.rax" in script_content:
                patterns.append("x64_register_manipulation_success")
            elif "arm" in result.architecture and "context.r0" in script_content:
                patterns.append("arm_register_manipulation_success")
        
        return patterns
    
    def _analyze_problematic_code(self, script_content: str, result: ScriptExecutionResult) -> List[str]:
        """Analyze code to identify problematic patterns"""
        patterns = []
        
        # Look for problematic constructs
        if "eval(" in script_content:
            patterns.append("dangerous_eval_usage")
        
        if result.execution_status == ExecutionStatus.TIMEOUT:
            if "while(true)" in script_content or "for(;;)" in script_content:
                patterns.append("infinite_loop_detected")
        
        # Check for common mistakes
        if "Permission denied" in str(result.errors):
            if "Memory.protect" not in script_content:
                patterns.append("missing_memory_protection_change")
        
        return patterns
    
    def _generate_improvements(self, script: GeneratedScript, result: ScriptExecutionResult) -> List[str]:
        """Generate improvement suggestions based on execution result"""
        improvements = []
        
        if result.execution_status == ExecutionStatus.FAILURE:
            # Suggest improvements based on failure type
            if "permission" in str(result.errors).lower():
                improvements.append("Add Memory.protect() to change memory permissions before writing")
            
            if "not found" in str(result.errors).lower():
                improvements.append("Add error handling for missing functions/modules")
                improvements.append("Use Process.enumerateModules() to verify module presence")
            
            if result.execution_time > 10.0:
                improvements.append("Optimize script performance - consider async operations")
        
        elif result.execution_status == ExecutionStatus.PARTIAL_SUCCESS:
            # Suggest completeness improvements
            if result.functions_hooked == 0:
                improvements.append("No functions were hooked - verify function addresses")
            
            if not result.protection_bypassed and result.target_protection:
                improvements.append(f"Protection {result.target_protection.value} not fully bypassed")
        
        # Performance improvements
        if result.cpu_usage > 50.0:
            improvements.append("High CPU usage detected - optimize loops and operations")
        
        if result.memory_usage > 100.0:  # MB
            improvements.append("High memory usage - consider freeing unused resources")
        
        return improvements
    
    def _store_feedback(self, feedback: FeedbackEntry):
        """Store feedback in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO feedback_entries 
            (feedback_id, timestamp, feedback_type, script_id, rating, comments, 
             execution_result, success_patterns, failure_patterns, improvements)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            feedback.feedback_id,
            feedback.timestamp.isoformat(),
            feedback.feedback_type.value,
            feedback.script_id,
            feedback.rating,
            feedback.comments,
            json.dumps(feedback.execution_result.to_dict()) if feedback.execution_result else None,
            json.dumps(feedback.success_patterns),
            json.dumps(feedback.failure_patterns),
            json.dumps(feedback.improvements)
        ))
        
        conn.commit()
        conn.close()
        
        # Add to buffer for batch processing
        self._feedback_buffer.append(feedback)
        
        # Process buffer if it's getting large
        if len(self._feedback_buffer) >= 10:
            self._process_feedback_buffer()
    
    def _update_pattern_knowledge(self, feedback: FeedbackEntry):
        """Update pattern knowledge based on feedback"""
        
        # Update success patterns
        for pattern in feedback.success_patterns:
            self._update_single_pattern(
                pattern, 
                "success", 
                feedback.script_id,
                feedback.execution_result
            )
        
        # Update failure patterns
        for pattern in feedback.failure_patterns:
            self._update_single_pattern(
                pattern, 
                "failure", 
                feedback.script_id,
                feedback.execution_result
            )
    
    def _update_single_pattern(self, pattern: str, pattern_type: str, 
                              script_id: str, execution_result: Optional[ScriptExecutionResult]):
        """Update knowledge about a single pattern"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if pattern exists
        cursor.execute(
            'SELECT * FROM pattern_knowledge WHERE pattern_id = ?',
            (pattern,)
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update existing pattern
            occurrence_count = existing[8] + 1
            success_rate = (existing[9] * existing[8] + (1.0 if pattern_type == "success" else 0.0)) / occurrence_count
            
            cursor.execute('''
                UPDATE pattern_knowledge 
                SET occurrence_count = ?, success_rate = ?, last_seen = ?
                WHERE pattern_id = ?
            ''', (occurrence_count, success_rate, datetime.now().isoformat(), pattern))
        else:
            # Create new pattern entry
            pattern_knowledge = PatternKnowledge(
                pattern_id=pattern,
                pattern_type=pattern_type,
                pattern_description=f"Pattern: {pattern}",
                script_type=ScriptType.FRIDA,  # Default, should be extracted properly
                protection_type=execution_result.target_protection if execution_result else None,
                architecture=execution_result.architecture if execution_result else None,
                code_snippet="",  # Would need to extract relevant code
                occurrence_count=1,
                success_rate=1.0 if pattern_type == "success" else 0.0,
                last_seen=datetime.now()
            )
            
            cursor.execute('''
                INSERT INTO pattern_knowledge 
                (pattern_id, pattern_type, pattern_description, script_type, protection_type,
                 architecture, code_snippet, context, occurrence_count, success_rate, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern_knowledge.pattern_id,
                pattern_knowledge.pattern_type,
                pattern_knowledge.pattern_description,
                pattern_knowledge.script_type.value,
                pattern_knowledge.protection_type.value if pattern_knowledge.protection_type else None,
                pattern_knowledge.architecture,
                pattern_knowledge.code_snippet,
                json.dumps(pattern_knowledge.context),
                pattern_knowledge.occurrence_count,
                pattern_knowledge.success_rate,
                pattern_knowledge.last_seen.isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def _update_script_performance(self, script: GeneratedScript, result: ScriptExecutionResult):
        """Update script performance metrics"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        script_id = script.metadata.get("script_id", "unknown")
        
        # Get existing performance data
        cursor.execute(
            'SELECT * FROM script_performance WHERE script_id = ?',
            (script_id,)
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update existing record
            total_executions = existing[3] + 1
            successful_executions = existing[4] + (1 if result.execution_status == ExecutionStatus.SUCCESS else 0)
            avg_time = (existing[5] * existing[3] + result.execution_time) / total_executions
            
            cursor.execute('''
                UPDATE script_performance 
                SET total_executions = ?, successful_executions = ?, 
                    average_execution_time = ?, last_execution = ?
                WHERE script_id = ?
            ''', (total_executions, successful_executions, avg_time, 
                  datetime.now().isoformat(), script_id))
        else:
            # Create new record
            cursor.execute('''
                INSERT INTO script_performance 
                (script_id, script_type, target_protection, total_executions, 
                 successful_executions, average_execution_time, last_execution, overall_rating)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                script_id,
                script.script_type.value,
                script.target_protection.value if script.target_protection else None,
                1,
                1 if result.execution_status == ExecutionStatus.SUCCESS else 0,
                result.execution_time,
                datetime.now().isoformat(),
                0.0
            ))
        
        conn.commit()
        conn.close()
    
    def _process_feedback_buffer(self):
        """Process accumulated feedback for learning"""
        
        if not self._feedback_buffer:
            return
        
        # Use AI to analyze patterns
        self._ai_analyze_feedback_batch(self._feedback_buffer)
        
        # Clear buffer
        self._feedback_buffer.clear()
    
    def _ai_analyze_feedback_batch(self, feedback_batch: List[FeedbackEntry]):
        """Use AI to analyze batch of feedback"""
        
        # Prepare context for AI analysis
        context = {
            "feedback_count": len(feedback_batch),
            "success_count": sum(1 for f in feedback_batch if f.execution_result and 
                               f.execution_result.execution_status == ExecutionStatus.SUCCESS),
            "failure_count": sum(1 for f in feedback_batch if f.execution_result and 
                               f.execution_result.execution_status == ExecutionStatus.FAILURE),
            "common_errors": self._extract_common_errors(feedback_batch),
            "common_successes": self._extract_common_successes(feedback_batch)
        }
        
        prompt = f"""Analyze the following batch of script execution feedback to identify learning opportunities:

Feedback Summary:
{json.dumps(context, indent=2)}

Individual Feedback Entries:
{json.dumps([f.to_dict() for f in feedback_batch[:5]], indent=2)}  # Limit to first 5 for context

Please provide:
1. Key patterns in successful executions
2. Common failure modes and their root causes
3. Specific code improvements that would increase success rate
4. Architecture-specific considerations
5. Protection-specific insights

Format your response with clear sections and actionable recommendations."""
        
        # Query consensus engine
        consensus_result = self.consensus_engine.generate_script_with_consensus(
            prompt=prompt,
            script_type="feedback_analysis",
            context_data={"feedback_batch": [f.to_dict() for f in feedback_batch]},
            required_expertise={ModelExpertise.REVERSE_ENGINEERING, ModelExpertise.MALWARE_ANALYSIS}
        )
        
        # Store AI insights
        self._store_ai_insights(consensus_result)
    
    def _extract_common_errors(self, feedback_batch: List[FeedbackEntry]) -> Dict[str, int]:
        """Extract common errors from feedback batch"""
        error_counts = {}
        
        for feedback in feedback_batch:
            if feedback.execution_result and feedback.execution_result.errors:
                for error in feedback.execution_result.errors:
                    # Categorize errors
                    if "permission" in error.lower():
                        error_type = "permission_error"
                    elif "not found" in error.lower():
                        error_type = "not_found_error"
                    elif "timeout" in error.lower():
                        error_type = "timeout_error"
                    else:
                        error_type = "other_error"
                    
                    error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        return error_counts
    
    def _extract_common_successes(self, feedback_batch: List[FeedbackEntry]) -> Dict[str, int]:
        """Extract common success patterns from feedback batch"""
        success_counts = {}
        
        for feedback in feedback_batch:
            if feedback.success_patterns:
                for pattern in feedback.success_patterns:
                    success_counts[pattern] = success_counts.get(pattern, 0) + 1
        
        return success_counts
    
    def _store_ai_insights(self, consensus_result: ConsensusResult):
        """Store AI-generated insights"""
        
        # Extract insights from consensus result
        insights = self._parse_ai_insights(consensus_result.consensus_content)
        
        # Update pattern knowledge with AI insights
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for pattern_id, ai_analysis in insights.items():
            cursor.execute('''
                UPDATE pattern_knowledge 
                SET ai_analysis = ?
                WHERE pattern_id = ?
            ''', (ai_analysis, pattern_id))
        
        conn.commit()
        conn.close()
    
    def _parse_ai_insights(self, ai_response: str) -> Dict[str, str]:
        """Parse AI insights from response"""
        insights = {}
        
        # Simple parsing - in practice would be more sophisticated
        sections = ai_response.split('\n\n')
        current_pattern = None
        
        for section in sections:
            if section.startswith('Pattern:'):
                current_pattern = section.split(':', 1)[1].strip()
            elif current_pattern and section.strip():
                insights[current_pattern] = section.strip()
        
        return insights
    
    def get_pattern_recommendations(self, script_type: ScriptType, 
                                   protection_type: Optional[ProtectionType],
                                   architecture: Optional[str]) -> List[PatternKnowledge]:
        """Get recommended patterns based on historical success"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Query for successful patterns
        query = '''
            SELECT * FROM pattern_knowledge 
            WHERE pattern_type = 'success' 
            AND script_type = ?
        '''
        params = [script_type.value]
        
        if protection_type:
            query += ' AND protection_type = ?'
            params.append(protection_type.value)
        
        if architecture:
            query += ' AND architecture = ?'
            params.append(architecture)
        
        query += ' ORDER BY success_rate DESC, occurrence_count DESC LIMIT 10'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        patterns = []
        for row in rows:
            pattern = PatternKnowledge(
                pattern_id=row[0],
                pattern_type=row[1],
                pattern_description=row[2],
                script_type=ScriptType(row[3]),
                protection_type=ProtectionType(row[4]) if row[4] else None,
                architecture=row[5],
                code_snippet=row[6],
                context=json.loads(row[7]) if row[7] else {},
                occurrence_count=row[8],
                success_rate=row[9],
                last_seen=datetime.fromisoformat(row[10]) if row[10] else None,
                ai_analysis=row[11],
                recommended_alternatives=json.loads(row[12]) if row[12] else []
            )
            patterns.append(pattern)
        
        conn.close()
        return patterns
    
    def get_antipatterns(self, script_type: ScriptType,
                         protection_type: Optional[ProtectionType]) -> List[PatternKnowledge]:
        """Get patterns to avoid based on historical failures"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Query for failure patterns
        query = '''
            SELECT * FROM pattern_knowledge 
            WHERE pattern_type = 'failure' 
            AND script_type = ?
            AND success_rate < 0.2
        '''
        params = [script_type.value]
        
        if protection_type:
            query += ' AND protection_type = ?'
            params.append(protection_type.value)
        
        query += ' ORDER BY occurrence_count DESC LIMIT 10'
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        antipatterns = []
        for row in rows:
            pattern = PatternKnowledge(
                pattern_id=row[0],
                pattern_type=row[1],
                pattern_description=row[2],
                script_type=ScriptType(row[3]),
                protection_type=ProtectionType(row[4]) if row[4] else None,
                architecture=row[5],
                code_snippet=row[6],
                context=json.loads(row[7]) if row[7] else {},
                occurrence_count=row[8],
                success_rate=row[9],
                last_seen=datetime.fromisoformat(row[10]) if row[10] else None,
                ai_analysis=row[11],
                recommended_alternatives=json.loads(row[12]) if row[12] else []
            )
            antipatterns.append(pattern)
        
        conn.close()
        return antipatterns
    
    def enhance_script_with_knowledge(self, script: GeneratedScript, 
                                    unified_model: Optional[UnifiedBinaryModel] = None) -> GeneratedScript:
        """Enhance script using learned patterns"""
        
        # Get successful patterns for this scenario
        successful_patterns = self.get_pattern_recommendations(
            script.script_type,
            script.target_protection,
            unified_model.metadata.architecture if unified_model else None
        )
        
        # Get patterns to avoid
        antipatterns = self.get_antipatterns(
            script.script_type,
            script.target_protection
        )
        
        # Apply enhancements
        enhanced_content = script.content
        
        # Add successful patterns
        for pattern in successful_patterns[:3]:  # Top 3 patterns
            if pattern.code_snippet and pattern.code_snippet not in enhanced_content:
                # Add pattern with comment
                pattern_comment = f"\n// Successful pattern: {pattern.pattern_description} (success rate: {pattern.success_rate:.2f})\n"
                enhanced_content = pattern_comment + pattern.code_snippet + "\n" + enhanced_content
        
        # Remove antipatterns
        for antipattern in antipatterns:
            if antipattern.code_snippet and antipattern.code_snippet in enhanced_content:
                # Replace with recommended alternative if available
                if antipattern.recommended_alternatives:
                    enhanced_content = enhanced_content.replace(
                        antipattern.code_snippet,
                        antipattern.recommended_alternatives[0]
                    )
                else:
                    # Just remove it
                    enhanced_content = enhanced_content.replace(antipattern.code_snippet, "")
        
        # Update script
        script.content = enhanced_content
        script.metadata["knowledge_enhanced"] = True
        script.metadata["patterns_applied"] = len(successful_patterns)
        script.metadata["antipatterns_removed"] = len(antipatterns)
        
        return script
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate performance report from feedback data"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Overall statistics
        cursor.execute('SELECT COUNT(*) FROM feedback_entries')
        total_feedback = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM pattern_knowledge WHERE pattern_type = "success"')
        success_patterns = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM pattern_knowledge WHERE pattern_type = "failure"')
        failure_patterns = cursor.fetchone()[0]
        
        # Script performance by type
        cursor.execute('''
            SELECT script_type, 
                   AVG(CAST(successful_executions AS FLOAT) / total_executions) as success_rate,
                   AVG(average_execution_time) as avg_time
            FROM script_performance
            GROUP BY script_type
        ''')
        performance_by_type = cursor.fetchall()
        
        # Most successful patterns
        cursor.execute('''
            SELECT pattern_id, pattern_description, success_rate, occurrence_count
            FROM pattern_knowledge
            WHERE pattern_type = "success"
            ORDER BY success_rate DESC, occurrence_count DESC
            LIMIT 5
        ''')
        top_patterns = cursor.fetchall()
        
        # Most problematic patterns
        cursor.execute('''
            SELECT pattern_id, pattern_description, success_rate, occurrence_count
            FROM pattern_knowledge
            WHERE pattern_type = "failure"
            ORDER BY occurrence_count DESC
            LIMIT 5
        ''')
        problematic_patterns = cursor.fetchall()
        
        conn.close()
        
        report = {
            "summary": {
                "total_feedback_entries": total_feedback,
                "success_patterns_identified": success_patterns,
                "failure_patterns_identified": failure_patterns,
                "knowledge_base_size": success_patterns + failure_patterns
            },
            "performance_by_script_type": [
                {
                    "script_type": row[0],
                    "success_rate": row[1] or 0.0,
                    "average_execution_time": row[2] or 0.0
                }
                for row in performance_by_type
            ],
            "top_success_patterns": [
                {
                    "pattern": row[0],
                    "description": row[1],
                    "success_rate": row[2],
                    "occurrences": row[3]
                }
                for row in top_patterns
            ],
            "problematic_patterns": [
                {
                    "pattern": row[0],
                    "description": row[1],
                    "success_rate": row[2],
                    "occurrences": row[3]
                }
                for row in problematic_patterns
            ],
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on feedback analysis"""
        
        recommendations = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for low success rates
        cursor.execute('''
            SELECT script_type, AVG(CAST(successful_executions AS FLOAT) / total_executions) as success_rate
            FROM script_performance
            GROUP BY script_type
            HAVING success_rate < 0.5
        ''')
        low_success_types = cursor.fetchall()
        
        for script_type, success_rate in low_success_types:
            recommendations.append(
                f"Improve {script_type} scripts - current success rate: {success_rate:.2%}"
            )
        
        # Check for common failures
        cursor.execute('''
            SELECT pattern_id, occurrence_count
            FROM pattern_knowledge
            WHERE pattern_type = "failure"
            AND occurrence_count > 5
            ORDER BY occurrence_count DESC
            LIMIT 3
        ''')
        common_failures = cursor.fetchall()
        
        for pattern_id, count in common_failures:
            recommendations.append(
                f"Address recurring issue: {pattern_id} (occurred {count} times)"
            )
        
        conn.close()
        
        return recommendations
    
    def record_user_feedback(self, script_id: str, rating: float, comments: Optional[str] = None):
        """Record user feedback for a script"""
        
        feedback = FeedbackEntry(
            feedback_id=f"user_{script_id}_{int(time.time())}",
            timestamp=datetime.now(),
            feedback_type=FeedbackType.USER_RATING,
            script_id=script_id,
            rating=rating,
            comments=comments
        )
        
        self._store_feedback(feedback)
        
        # Update overall script rating
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE script_performance
            SET overall_rating = (overall_rating + ?) / 2
            WHERE script_id = ?
        ''', (rating, script_id))
        
        conn.commit()
        conn.close()
    
    def export_knowledge_base(self, output_path: str):
        """Export knowledge base for backup or sharing"""
        
        conn = sqlite3.connect(self.db_path)
        
        # Export all tables to JSON
        knowledge_export = {
            "export_date": datetime.now().isoformat(),
            "feedback_entries": [],
            "pattern_knowledge": [],
            "script_performance": []
        }
        
        # Export feedback entries
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM feedback_entries')
        for row in cursor.fetchall():
            knowledge_export["feedback_entries"].append({
                "feedback_id": row[0],
                "timestamp": row[1],
                "feedback_type": row[2],
                "script_id": row[3],
                "rating": row[4],
                "comments": row[5],
                "execution_result": json.loads(row[6]) if row[6] else None,
                "success_patterns": json.loads(row[7]) if row[7] else [],
                "failure_patterns": json.loads(row[8]) if row[8] else [],
                "improvements": json.loads(row[9]) if row[9] else []
            })
        
        # Export pattern knowledge
        cursor.execute('SELECT * FROM pattern_knowledge')
        for row in cursor.fetchall():
            knowledge_export["pattern_knowledge"].append({
                "pattern_id": row[0],
                "pattern_type": row[1],
                "pattern_description": row[2],
                "script_type": row[3],
                "protection_type": row[4],
                "architecture": row[5],
                "code_snippet": row[6],
                "context": json.loads(row[7]) if row[7] else {},
                "occurrence_count": row[8],
                "success_rate": row[9],
                "last_seen": row[10],
                "ai_analysis": row[11],
                "recommended_alternatives": json.loads(row[12]) if row[12] else []
            })
        
        # Export script performance
        cursor.execute('SELECT * FROM script_performance')
        for row in cursor.fetchall():
            knowledge_export["script_performance"].append({
                "script_id": row[0],
                "script_type": row[1],
                "target_protection": row[2],
                "total_executions": row[3],
                "successful_executions": row[4],
                "average_execution_time": row[5],
                "last_execution": row[6],
                "overall_rating": row[7]
            })
        
        conn.close()
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(knowledge_export, f, indent=2)
        
        logger.info(f"Knowledge base exported to {output_path}")
    
    def import_knowledge_base(self, import_path: str):
        """Import knowledge base from backup"""
        
        with open(import_path, 'r') as f:
            knowledge_import = json.load(f)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Import feedback entries
        for entry in knowledge_import.get("feedback_entries", []):
            cursor.execute('''
                INSERT OR REPLACE INTO feedback_entries 
                (feedback_id, timestamp, feedback_type, script_id, rating, comments, 
                 execution_result, success_patterns, failure_patterns, improvements)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                entry["feedback_id"],
                entry["timestamp"],
                entry["feedback_type"],
                entry["script_id"],
                entry["rating"],
                entry["comments"],
                json.dumps(entry["execution_result"]) if entry["execution_result"] else None,
                json.dumps(entry["success_patterns"]),
                json.dumps(entry["failure_patterns"]),
                json.dumps(entry["improvements"])
            ))
        
        # Import pattern knowledge
        for pattern in knowledge_import.get("pattern_knowledge", []):
            cursor.execute('''
                INSERT OR REPLACE INTO pattern_knowledge 
                (pattern_id, pattern_type, pattern_description, script_type, protection_type,
                 architecture, code_snippet, context, occurrence_count, success_rate, last_seen,
                 ai_analysis, recommended_alternatives)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern["pattern_id"],
                pattern["pattern_type"],
                pattern["pattern_description"],
                pattern["script_type"],
                pattern["protection_type"],
                pattern["architecture"],
                pattern["code_snippet"],
                json.dumps(pattern["context"]),
                pattern["occurrence_count"],
                pattern["success_rate"],
                pattern["last_seen"],
                pattern["ai_analysis"],
                json.dumps(pattern["recommended_alternatives"])
            ))
        
        # Import script performance
        for perf in knowledge_import.get("script_performance", []):
            cursor.execute('''
                INSERT OR REPLACE INTO script_performance 
                (script_id, script_type, target_protection, total_executions, 
                 successful_executions, average_execution_time, last_execution, overall_rating)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                perf["script_id"],
                perf["script_type"],
                perf["target_protection"],
                perf["total_executions"],
                perf["successful_executions"],
                perf["average_execution_time"],
                perf["last_execution"],
                perf["overall_rating"]
            ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Knowledge base imported from {import_path}")