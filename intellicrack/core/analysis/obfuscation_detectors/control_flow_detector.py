"""
Control Flow Obfuscation Detection Engine

Specialized detection for control flow obfuscation techniques including:
- Control flow flattening
- Opaque predicates
- Bogus control flow
- Jump table obfuscation

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
import networkx as nx
import numpy as np
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from ....utils.logger import get_logger

logger = get_logger(__name__)

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


@dataclass
class ControlFlowMetrics:
    """Metrics for control flow analysis"""
    basic_blocks: int
    edges: int
    cyclomatic_complexity: int
    nesting_depth: int
    branch_factor: float
    dominator_tree_height: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'basic_blocks': self.basic_blocks,
            'edges': self.edges,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'nesting_depth': self.nesting_depth,
            'branch_factor': self.branch_factor,
            'dominator_tree_height': self.dominator_tree_height
        }


@dataclass
class OpaquePredicatePattern:
    """Opaque predicate detection result"""
    address: int
    predicate_type: str  # 'always_true', 'always_false', 'contextual'
    expression: str
    confidence: float
    analysis_method: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'address': self.address,
            'predicate_type': self.predicate_type,
            'expression': self.expression,
            'confidence': self.confidence,
            'analysis_method': self.analysis_method
        }


class ControlFlowObfuscationDetector:
    """Advanced control flow obfuscation detection engine"""
    
    def __init__(self, r2_session: Optional[Any] = None):
        """Initialize control flow detector
        
        Args:
            r2_session: Optional radare2 session
        """
        self.r2 = r2_session
        self.logger = logger
        
        # Detection thresholds
        self.flattening_threshold = 0.7
        self.opaque_predicate_threshold = 0.6
        self.complexity_threshold = 15
        
    def detect_control_flow_flattening(self, func_addr: int) -> Dict[str, Any]:
        """Detect control flow flattening in a function
        
        Args:
            func_addr: Function address to analyze
            
        Returns:
            Detection results with confidence scores
        """
        if not self.r2:
            return {'error': 'No radare2 session available'}
        
        try:
            # Get function control flow graph
            cfg = self._get_function_cfg(func_addr)
            if not cfg:
                return {'error': 'Failed to get CFG'}
            
            # Calculate metrics
            metrics = self._calculate_cfg_metrics(cfg)
            
            # Detect flattening patterns
            flattening_indicators = []
            confidence = 0.0
            
            # Check for dispatcher pattern
            dispatcher_score = self._detect_dispatcher_pattern(func_addr, cfg)
            if dispatcher_score > 0.5:
                flattening_indicators.append('dispatcher_pattern')
                confidence += dispatcher_score * 0.4
            
            # Check for state variable usage
            state_var_score = self._detect_state_variables(func_addr)
            if state_var_score > 0.5:
                flattening_indicators.append('state_variables')
                confidence += state_var_score * 0.3
            
            # Check for unnatural control flow
            unnatural_score = self._detect_unnatural_control_flow(cfg, metrics)
            if unnatural_score > 0.5:
                flattening_indicators.append('unnatural_control_flow')
                confidence += unnatural_score * 0.3
            
            return {
                'detected': confidence > self.flattening_threshold,
                'confidence': min(confidence, 1.0),
                'indicators': flattening_indicators,
                'metrics': metrics.to_dict(),
                'dispatcher_score': dispatcher_score,
                'state_variable_score': state_var_score,
                'unnatural_flow_score': unnatural_score
            }
            
        except Exception as e:
            self.logger.error(f"Control flow flattening detection failed: {e}")
            return {'error': str(e)}
    
    def detect_opaque_predicates(self, func_addr: int) -> List[OpaquePredicatePattern]:
        """Detect opaque predicates in a function
        
        Args:
            func_addr: Function address to analyze
            
        Returns:
            List of detected opaque predicates
        """
        predicates = []
        
        if not self.r2:
            return predicates
        
        try:
            # Get basic blocks
            blocks = self.r2.cmdj(f"afbj @ {func_addr}") or []
            
            for block in blocks:
                block_addr = block.get('addr', 0)
                
                # Analyze conditional branches in block
                branch_predicates = self._analyze_conditional_branches(block_addr)
                predicates.extend(branch_predicates)
                
                # Check for mathematical opaque predicates
                math_predicates = self._detect_mathematical_predicates(block_addr)
                predicates.extend(math_predicates)
                
                # Look for contextual opaque predicates
                contextual_predicates = self._detect_contextual_predicates(block_addr)
                predicates.extend(contextual_predicates)
            
            # Filter by confidence threshold
            return [p for p in predicates if p.confidence > self.opaque_predicate_threshold]
            
        except Exception as e:
            self.logger.error(f"Opaque predicate detection failed: {e}")
            return []
    
    def detect_bogus_control_flow(self, func_addr: int) -> Dict[str, Any]:
        """Detect bogus control flow insertion
        
        Args:
            func_addr: Function address to analyze
            
        Returns:
            Detection results with identified bogus blocks
        """
        if not self.r2:
            return {'error': 'No radare2 session available'}
        
        try:
            cfg = self._get_function_cfg(func_addr)
            if not cfg:
                return {'error': 'Failed to get CFG'}
            
            bogus_blocks = []
            unreachable_blocks = []
            dead_code_blocks = []
            
            blocks = cfg.get('blocks', [])
            
            for block in blocks:
                block_addr = block.get('offset', 0)
                
                # Check for unreachable blocks
                if self._is_unreachable_block(block_addr, cfg):
                    unreachable_blocks.append({
                        'address': block_addr,
                        'size': block.get('size', 0),
                        'type': 'unreachable'
                    })
                
                # Check for dead code
                dead_code_ratio = self._calculate_dead_code_ratio(block_addr)
                if dead_code_ratio > 0.5:
                    dead_code_blocks.append({
                        'address': block_addr,
                        'dead_code_ratio': dead_code_ratio,
                        'type': 'dead_code'
                    })
                
                # Check for bogus jumps
                if self._has_bogus_jumps(block_addr):
                    bogus_blocks.append({
                        'address': block_addr,
                        'type': 'bogus_jumps'
                    })
            
            total_bogus = len(unreachable_blocks) + len(dead_code_blocks) + len(bogus_blocks)
            confidence = min(total_bogus / len(blocks), 1.0) if blocks else 0.0
            
            return {
                'detected': total_bogus > 0,
                'confidence': confidence,
                'unreachable_blocks': unreachable_blocks,
                'dead_code_blocks': dead_code_blocks,
                'bogus_blocks': bogus_blocks,
                'total_blocks': len(blocks),
                'bogus_ratio': confidence
            }
            
        except Exception as e:
            self.logger.error(f"Bogus control flow detection failed: {e}")
            return {'error': str(e)}
    
    def detect_jump_table_obfuscation(self, func_addr: int) -> Dict[str, Any]:
        """Detect jump table obfuscation
        
        Args:
            func_addr: Function address to analyze
            
        Returns:
            Detection results for jump table obfuscation
        """
        if not self.r2:
            return {'error': 'No radare2 session available'}
        
        try:
            # Look for switch statements
            switch_refs = self.r2.cmd(f"aaef @ {func_addr}")
            
            jump_tables = []
            obfuscated_tables = []
            
            # Analyze jump table structure
            disasm = self.r2.cmd(f"pdf @ {func_addr}")
            
            if 'switch' in disasm.lower():
                # Get jump references
                jump_refs = self.r2.cmdj(f"axtj @ {func_addr}") or []
                
                # Analyze jump table characteristics
                table_analysis = self._analyze_jump_table_structure(func_addr, jump_refs)
                
                if table_analysis['is_obfuscated']:
                    obfuscated_tables.append(table_analysis)
                else:
                    jump_tables.append(table_analysis)
            
            confidence = len(obfuscated_tables) / max(len(jump_tables) + len(obfuscated_tables), 1)
            
            return {
                'detected': len(obfuscated_tables) > 0,
                'confidence': confidence,
                'normal_jump_tables': jump_tables,
                'obfuscated_jump_tables': obfuscated_tables,
                'total_jump_tables': len(jump_tables) + len(obfuscated_tables)
            }
            
        except Exception as e:
            self.logger.error(f"Jump table obfuscation detection failed: {e}")
            return {'error': str(e)}
    
    def _get_function_cfg(self, func_addr: int) -> Optional[Dict[str, Any]]:
        """Get function control flow graph"""
        if not self.r2:
            return None
        
        try:
            return self.r2.cmdj(f"agfj @ {func_addr}")
        except:
            return None
    
    def _calculate_cfg_metrics(self, cfg: Dict[str, Any]) -> ControlFlowMetrics:
        """Calculate control flow graph metrics"""
        blocks = cfg.get('blocks', [])
        edges = 0
        
        # Count edges
        for block in blocks:
            if block.get('jump'):
                edges += 1
            if block.get('fail'):
                edges += 1
        
        # Calculate cyclomatic complexity (M = E - N + 2P)
        # where E = edges, N = nodes, P = connected components
        basic_blocks = len(blocks)
        cyclomatic_complexity = edges - basic_blocks + 2
        
        # Calculate nesting depth (simplified)
        nesting_depth = self._calculate_nesting_depth(blocks)
        
        # Calculate branch factor
        branch_factor = edges / basic_blocks if basic_blocks > 0 else 0.0
        
        # Calculate dominator tree height (simplified)
        dominator_tree_height = self._calculate_dominator_height(blocks)
        
        return ControlFlowMetrics(
            basic_blocks=basic_blocks,
            edges=edges,
            cyclomatic_complexity=cyclomatic_complexity,
            nesting_depth=nesting_depth,
            branch_factor=branch_factor,
            dominator_tree_height=dominator_tree_height
        )
    
    def _detect_dispatcher_pattern(self, func_addr: int, cfg: Dict[str, Any]) -> float:
        """Detect dispatcher pattern typical of control flow flattening"""
        blocks = cfg.get('blocks', [])
        
        if len(blocks) < 3:
            return 0.0
        
        # Look for a central block with many outgoing edges
        max_outgoing = 0
        dispatcher_candidates = 0
        
        for block in blocks:
            outgoing = 0
            if block.get('jump'):
                outgoing += 1
            if block.get('fail'):
                outgoing += 1
            
            max_outgoing = max(max_outgoing, outgoing)
            
            # Blocks with many outgoing edges are dispatcher candidates
            if outgoing > len(blocks) * 0.3:
                dispatcher_candidates += 1
        
        # High max outgoing edges and few dispatcher candidates suggests flattening
        if max_outgoing > len(blocks) * 0.5 and dispatcher_candidates <= 2:
            return 0.8
        elif max_outgoing > len(blocks) * 0.3:
            return 0.6
        
        return 0.0
    
    def _detect_state_variables(self, func_addr: int) -> float:
        """Detect state variable usage patterns"""
        if not self.r2:
            return 0.0
        
        disasm = self.r2.cmd(f"pdf @ {func_addr}")
        
        # Look for state variable patterns
        state_indicators = 0
        total_instructions = len(disasm.split('\n'))
        
        # Count state-related operations
        state_patterns = ['mov.*state', 'cmp.*state', 'switch', 'case']
        
        for pattern in state_patterns:
            if pattern in disasm.lower():
                state_indicators += 1
        
        # Look for repeated variable assignments
        mov_count = disasm.lower().count('mov ')
        if mov_count > total_instructions * 0.3:
            state_indicators += 1
        
        return min(state_indicators / 3.0, 1.0)
    
    def _detect_unnatural_control_flow(self, cfg: Dict[str, Any], metrics: ControlFlowMetrics) -> float:
        """Detect unnatural control flow patterns"""
        score = 0.0
        
        # High cyclomatic complexity
        if metrics.cyclomatic_complexity > self.complexity_threshold:
            score += 0.3
        
        # Unusual branch factor
        if metrics.branch_factor > 3.0:
            score += 0.3
        
        # Check for many single-instruction blocks
        blocks = cfg.get('blocks', [])
        small_blocks = sum(1 for block in blocks if block.get('size', 0) < 10)
        
        if small_blocks > len(blocks) * 0.6:
            score += 0.4
        
        return min(score, 1.0)    def _analyze_conditional_branches(self, block_addr: int) -> List[OpaquePredicatePattern]:
        """Analyze conditional branches for opaque predicates"""
        predicates = []
        
        if not self.r2:
            return predicates
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        lines = disasm.split('\n')
        
        for i, line in enumerate(lines):
            line_clean = line.strip().lower()
            
            # Look for comparison instructions
            if any(cmp in line_clean for cmp in ['cmp', 'test']):
                # Check following lines for conditional jumps
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip().lower()
                    
                    # Analyze the predicate
                    predicate = self._analyze_predicate_pattern(line_clean, next_line)
                    if predicate:
                        predicates.append(OpaquePredicatePattern(
                            address=self._extract_address(line),
                            predicate_type=predicate['type'],
                            expression=line_clean,
                            confidence=predicate['confidence'],
                            analysis_method='conditional_branch_analysis'
                        ))
        
        return predicates
    
    def _analyze_predicate_pattern(self, cmp_line: str, branch_line: str) -> Optional[Dict[str, Any]]:
        """Analyze predicate pattern for opacity"""
        # Self-comparison always equal
        if 'cmp' in cmp_line:
            parts = cmp_line.split()
            if len(parts) >= 3:
                reg1 = parts[-2].rstrip(',')
                reg2 = parts[-1]
                if reg1 == reg2:
                    return {'type': 'always_true', 'confidence': 0.9}
        
        # Test self always zero (unless register is zero)
        if 'test' in cmp_line:
            parts = cmp_line.split()
            if len(parts) >= 3:
                reg1 = parts[-2].rstrip(',')
                reg2 = parts[-1]
                if reg1 == reg2:
                    return {'type': 'contextual', 'confidence': 0.7}
        
        # Zero comparison patterns
        if 'cmp' in cmp_line and ', 0' in cmp_line:
            if 'je' in branch_line or 'jz' in branch_line:
                return {'type': 'contextual', 'confidence': 0.6}
        
        return None
    
    def _detect_mathematical_predicates(self, block_addr: int) -> List[OpaquePredicatePattern]:
        """Detect mathematical opaque predicates"""
        predicates = []
        
        if not self.r2:
            return predicates
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        
        # Look for mathematical identities
        math_patterns = [
            # x^2 >= 0 patterns
            ('mul', 'cmp', 'jge'),  # x*x compared and jump if greater/equal
            # |x| >= 0 patterns  
            ('abs', 'cmp', 'jge'),
            # Even/odd predicates that are always predictable
            ('and', '1', 'cmp'),  # x & 1 for even/odd
        ]
        
        lines = disasm.split('\n')
        for i, line in enumerate(lines):
            # Check for mathematical identity patterns
            if self._contains_mathematical_identity(line, lines[i:i+3]):
                predicates.append(OpaquePredicatePattern(
                    address=self._extract_address(line),
                    predicate_type='always_true',
                    expression=line.strip(),
                    confidence=0.8,
                    analysis_method='mathematical_identity'
                ))
        
        return predicates
    
    def _contains_mathematical_identity(self, line: str, context: List[str]) -> bool:
        """Check if instruction sequence contains mathematical identity"""
        line_lower = line.lower()
        
        # Look for x^2 >= 0 pattern
        if 'mul' in line_lower:
            # Check if multiplying register by itself
            parts = line_lower.split()
            if len(parts) >= 3:
                reg1 = parts[-2].rstrip(',')
                reg2 = parts[-1]
                if reg1 == reg2:  # x * x
                    # Check if followed by comparison with zero
                    for next_line in context[1:3]:
                        if 'cmp' in next_line.lower() and '0' in next_line:
                            return True
        
        return False
    
    def _detect_contextual_predicates(self, block_addr: int) -> List[OpaquePredicatePattern]:
        """Detect contextual opaque predicates"""
        predicates = []
        
        if not self.r2:
            return predicates
        
        # Get function context
        func_info = self.r2.cmdj(f"afij @ {block_addr}")
        if not func_info:
            return predicates
        
        # Look for predicates that depend on program state
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        
        # Check for stack pointer comparisons
        if 'cmp.*sp' in disasm.lower():
            predicates.append(OpaquePredicatePattern(
                address=block_addr,
                predicate_type='contextual',
                expression='stack_pointer_comparison',
                confidence=0.5,
                analysis_method='contextual_analysis'
            ))
        
        # Check for time-based predicates
        if any(time_func in disasm.lower() for time_func in ['time', 'tick', 'rdtsc']):
            predicates.append(OpaquePredicatePattern(
                address=block_addr,
                predicate_type='contextual', 
                expression='time_based_predicate',
                confidence=0.6,
                analysis_method='contextual_analysis'
            ))
        
        return predicates
    
    def _calculate_nesting_depth(self, blocks: List[Dict[str, Any]]) -> int:
        """Calculate maximum nesting depth (simplified)"""
        # This is a simplified version - real implementation would need
        # proper loop detection and nesting analysis
        max_depth = 0
        
        for block in blocks:
            # Count nested structures by analyzing control flow
            # For now, use a simple heuristic based on jump patterns
            if block.get('jump') and block.get('fail'):
                max_depth = max(max_depth, 2)  # At least 2 levels
        
        return max_depth
    
    def _calculate_dominator_height(self, blocks: List[Dict[str, Any]]) -> int:
        """Calculate dominator tree height (simplified)"""
        # Simplified implementation - real version would build dominator tree
        return min(len(blocks), 10)  # Cap at 10 for reasonable values
    
    def _is_unreachable_block(self, block_addr: int, cfg: Dict[str, Any]) -> bool:
        """Check if block is unreachable"""
        # Build reachability from entry point
        blocks = cfg.get('blocks', [])
        
        if not blocks:
            return False
        
        # Get entry block (first block or block with no predecessors)
        entry_addr = blocks[0].get('offset', 0)
        
        # Simple reachability check
        reachable = {entry_addr}
        changed = True
        
        while changed:
            changed = False
            for block in blocks:
                block_addr_current = block.get('offset', 0)
                if block_addr_current in reachable:
                    # Add successors
                    if block.get('jump') and block['jump'] not in reachable:
                        reachable.add(block['jump'])
                        changed = True
                    if block.get('fail') and block['fail'] not in reachable:
                        reachable.add(block['fail'])
                        changed = True
        
        return block_addr not in reachable
    
    def _calculate_dead_code_ratio(self, block_addr: int) -> float:
        """Calculate ratio of dead code in block"""
        if not self.r2:
            return 0.0
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        lines = [line.strip() for line in disasm.split('\n') if line.strip()]
        
        if not lines:
            return 0.0
        
        dead_instructions = 0
        dead_patterns = ['nop', 'int3', 'ud2', 'hlt']
        
        for line in lines:
            if any(pattern in line.lower() for pattern in dead_patterns):
                dead_instructions += 1
        
        return dead_instructions / len(lines)
    
    def _has_bogus_jumps(self, block_addr: int) -> bool:
        """Check for bogus jump patterns"""
        if not self.r2:
            return False
        
        disasm = self.r2.cmd(f"pdb @ {block_addr}")
        
        # Look for jumps to immediate next instruction
        lines = disasm.split('\n')
        for i, line in enumerate(lines):
            if 'jmp' in line.lower() and i + 1 < len(lines):
                # Check if jumping to next instruction (bogus jump)
                current_addr = self._extract_address(line)
                if i + 1 < len(lines):
                    next_addr = self._extract_address(lines[i + 1])
                    if abs(next_addr - current_addr) < 10:  # Very close addresses
                        return True
        
        return False
    
    def _analyze_jump_table_structure(self, func_addr: int, jump_refs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze jump table structure for obfuscation"""
        analysis = {
            'address': func_addr,
            'target_count': len(jump_refs),
            'is_obfuscated': False,
            'obfuscation_indicators': []
        }
        
        # Check for excessive number of targets
        if len(jump_refs) > 50:
            analysis['obfuscation_indicators'].append('excessive_targets')
            analysis['is_obfuscated'] = True
        
        # Check for non-sequential targets (might indicate obfuscation)
        if jump_refs:
            addresses = [ref.get('addr', 0) for ref in jump_refs]
            addresses.sort()
            
            # Calculate gaps between addresses
            gaps = [addresses[i+1] - addresses[i] for i in range(len(addresses)-1)]
            avg_gap = sum(gaps) / len(gaps) if gaps else 0
            
            # Large variations in gaps might indicate obfuscation
            if gaps and max(gaps) > avg_gap * 10:
                analysis['obfuscation_indicators'].append('irregular_spacing')
                analysis['is_obfuscated'] = True
        
        return analysis
    
    def _extract_address(self, line: str) -> int:
        """Extract address from disassembly line"""
        import re
        match = re.search(r'0x([0-9a-fA-F]+)', line)
        if match:
            return int(match.group(1), 16)
        return 0