"""
Radare2 Advanced Decompilation Engine

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
import re
from typing import Any, Dict, List, Optional, Tuple

from ...utils.radare2_utils import R2Session, R2Exception, r2_session


class R2DecompilationEngine:
    """
    Advanced decompilation engine using radare2's pdc and pdg commands.
    
    Provides sophisticated pseudocode generation and analysis capabilities
    specifically tailored for license analysis and vulnerability detection.
    """

    def __init__(self, binary_path: str, radare2_path: Optional[str] = None):
        """
        Initialize decompilation engine.
        
        Args:
            binary_path: Path to binary file
            radare2_path: Optional path to radare2 executable
        """
        self.binary_path = binary_path
        self.radare2_path = radare2_path
        self.logger = logging.getLogger(__name__)
        self.decompilation_cache = {}

    def decompile_function(self, address: int, optimize: bool = True) -> Dict[str, Any]:
        """
        Decompile a single function with advanced analysis.
        
        Args:
            address: Function address
            optimize: Whether to apply optimization passes
            
        Returns:
            Comprehensive decompilation results
        """
        cache_key = f"{address}_{optimize}"
        if cache_key in self.decompilation_cache:
            return self.decompilation_cache[cache_key]

        result = {
            'address': hex(address),
            'pseudocode': '',
            'graph_data': {},
            'variables': [],
            'license_patterns': [],
            'vulnerability_patterns': [],
            'complexity_metrics': {},
            'api_calls': [],
            'string_references': [],
            'control_flow': {},
            'error': None
        }

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                # Get function info
                func_info = r2.get_function_info(address)
                if not func_info:
                    result['error'] = f"Function not found at address {hex(address)}"
                    return result

                # Generate pseudocode
                pseudocode = r2.decompile_function(address)
                result['pseudocode'] = pseudocode

                # Get function graph with decompilation annotations
                graph_data = r2.get_function_graph(address)
                result['graph_data'] = graph_data

                # Analyze variables
                result['variables'] = self._extract_variables(r2, address)

                # Detect license patterns in pseudocode
                result['license_patterns'] = self._detect_license_patterns(pseudocode)

                # Detect vulnerability patterns
                result['vulnerability_patterns'] = self._detect_vulnerability_patterns(pseudocode)

                # Calculate complexity metrics
                result['complexity_metrics'] = self._calculate_complexity(pseudocode, graph_data)

                # Extract API calls
                result['api_calls'] = self._extract_api_calls(pseudocode)

                # Get string references
                result['string_references'] = self._get_string_references(r2, address)

                # Analyze control flow
                result['control_flow'] = self._analyze_control_flow(graph_data)

                # Cache the result
                self.decompilation_cache[cache_key] = result

        except R2Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Decompilation failed for {hex(address)}: {e}")

        return result

    def decompile_all_functions(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Decompile all functions in the binary.
        
        Args:
            limit: Optional limit on number of functions to decompile
            
        Returns:
            Dictionary of function addresses to decompilation results
        """
        results = {}
        function_count = 0

        try:
            with r2_session(self.binary_path, self.radare2_path) as r2:
                functions = r2.get_functions()

                for func in functions:
                    if limit and function_count >= limit:
                        break

                    addr = func.get('offset')
                    if addr:
                        self.logger.info(f"Decompiling function {func.get('name', 'unknown')} at {hex(addr)}")
                        results[hex(addr)] = self.decompile_function(addr)
                        function_count += 1

        except R2Exception as e:
            self.logger.error(f"Failed to decompile functions: {e}")

        return results

    def _extract_variables(self, r2: R2Session, address: int) -> List[Dict[str, Any]]:
        """Extract function variables and their types."""
        variables = []
        
        try:
            # Get function variables
            var_info = r2._execute_command(f'afvj @ {hex(address)}', expect_json=True)
            
            if isinstance(var_info, list):
                for var in var_info:
                    variables.append({
                        'name': var.get('name', ''),
                        'type': var.get('type', ''),
                        'offset': var.get('delta', 0),
                        'kind': var.get('kind', ''),
                        'size': var.get('size', 0)
                    })
        except R2Exception:
            pass

        return variables

    def _detect_license_patterns(self, pseudocode: str) -> List[Dict[str, Any]]:
        """Detect license-related patterns in decompiled code."""
        patterns = []
        
        # License-related keywords
        license_keywords = [
            r'\b(?:license|licens)\b',
            r'\b(?:registration|register)\b',
            r'\b(?:activation|activate)\b',
            r'\b(?:serial|key)\b',
            r'\b(?:trial|demo)\b',
            r'\b(?:valid|validate|verification|verify)\b',
            r'\b(?:expire|expiration)\b',
            r'\b(?:authentic|auth)\b',
            r'\b(?:dongle|hwid)\b',
            r'\b(?:crack|pirate|illegal)\b'
        ]

        # License validation patterns
        validation_patterns = [
            r'if\s*\(\s*.*(?:license|key|valid).*\s*\)',
            r'while\s*\(\s*.*(?:trial|demo).*\s*\)',
            r'strcmp\s*\(\s*.*(?:serial|key).*\s*\)',
            r'strlen\s*\(\s*.*(?:license|key).*\s*\)',
            r'MessageBox.*(?:license|registration|trial)',
            r'exit\s*\(\s*.*\).*(?:license|trial)',
        ]

        lines = pseudocode.split('\n')
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Check for license keywords
            for pattern in license_keywords:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    patterns.append({
                        'type': 'license_keyword',
                        'pattern': pattern,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'confidence': 0.7
                    })

            # Check for validation patterns
            for pattern in validation_patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    patterns.append({
                        'type': 'license_validation',
                        'pattern': pattern,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'confidence': 0.9
                    })

        return patterns

    def _detect_vulnerability_patterns(self, pseudocode: str) -> List[Dict[str, Any]]:
        """Detect vulnerability patterns in decompiled code."""
        patterns = []
        
        # Buffer overflow patterns
        buffer_patterns = [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'sprintf\s*\(',
            r'gets\s*\(',
            r'scanf\s*\(',
            r'memcpy\s*\('
        ]

        # Format string patterns
        format_patterns = [
            r'printf\s*\(\s*[^"]*[^,\s]+\s*\)',
            r'fprintf\s*\(\s*[^,]*,\s*[^"]*[^,\s]+\s*\)',
            r'sprintf\s*\(\s*[^,]*,\s*[^"]*[^,\s]+\s*\)'
        ]

        # Memory management patterns
        memory_patterns = [
            r'free\s*\(\s*.*\s*\).*free\s*\(',  # Double free
            r'malloc\s*\(\s*.*\s*\).*(?!free)',  # Memory leak
            r'\*\s*\(\s*.*\s*\+\s*.*\s*\)',     # Potential buffer overrun
        ]

        lines = pseudocode.split('\n')
        for i, line in enumerate(lines):
            # Check buffer overflow patterns
            for pattern in buffer_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    patterns.append({
                        'type': 'buffer_overflow',
                        'pattern': pattern,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'severity': 'high'
                    })

            # Check format string patterns
            for pattern in format_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    patterns.append({
                        'type': 'format_string',
                        'pattern': pattern,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'severity': 'medium'
                    })

            # Check memory management patterns
            for pattern in memory_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    patterns.append({
                        'type': 'memory_management',
                        'pattern': pattern,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'severity': 'high'
                    })

        return patterns

    def _calculate_complexity(self, pseudocode: str, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate complexity metrics for decompiled function."""
        metrics = {
            'lines_of_code': 0,
            'cyclomatic_complexity': 1,
            'nesting_depth': 0,
            'number_of_branches': 0,
            'number_of_loops': 0,
            'cognitive_complexity': 0
        }

        if not pseudocode:
            return metrics

        lines = [line.strip() for line in pseudocode.split('\n') if line.strip()]
        metrics['lines_of_code'] = len(lines)

        # Calculate cyclomatic complexity
        branch_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', '&&', '||']
        for line in lines:
            for keyword in branch_keywords:
                metrics['cyclomatic_complexity'] += line.lower().count(keyword)

        # Calculate nesting depth
        current_depth = 0
        max_depth = 0
        for line in lines:
            if '{' in line:
                current_depth += line.count('{')
                max_depth = max(max_depth, current_depth)
            if '}' in line:
                current_depth -= line.count('}')

        metrics['nesting_depth'] = max_depth

        # Count branches and loops
        for line in lines:
            line_lower = line.lower()
            if any(keyword in line_lower for keyword in ['if', 'switch']):
                metrics['number_of_branches'] += 1
            if any(keyword in line_lower for keyword in ['while', 'for', 'do']):
                metrics['number_of_loops'] += 1

        # Cognitive complexity (simplified calculation)
        metrics['cognitive_complexity'] = (
            metrics['cyclomatic_complexity'] +
            metrics['nesting_depth'] * 2 +
            metrics['number_of_loops']
        )

        return metrics

    def _extract_api_calls(self, pseudocode: str) -> List[Dict[str, Any]]:
        """Extract API function calls from pseudocode."""
        api_calls = []
        
        # Common API patterns
        api_patterns = [
            r'(\w+)\s*\(',  # General function calls
            r'(Get\w+)\s*\(',  # Windows Get* APIs
            r'(Set\w+)\s*\(',  # Windows Set* APIs
            r'(Create\w+)\s*\(',  # Windows Create* APIs
            r'(Reg\w+)\s*\(',  # Registry APIs
            r'(Crypt\w+)\s*\(',  # Crypto APIs
        ]

        lines = pseudocode.split('\n')
        for i, line in enumerate(lines):
            for pattern in api_patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    api_calls.append({
                        'function': match,
                        'line': line.strip(),
                        'line_number': i + 1,
                        'context': 'decompiled_code'
                    })

        return api_calls

    def _get_string_references(self, r2: R2Session, address: int) -> List[Dict[str, Any]]:
        """Get string references used by the function."""
        strings = []
        
        try:
            # Get cross-references from the function
            xrefs = r2._execute_command(f'axfj @ {hex(address)}', expect_json=True)
            
            if isinstance(xrefs, list):
                for xref in xrefs:
                    if xref.get('type') == 'DATA':
                        addr = xref.get('addr')
                        if addr:
                            # Try to get string at address
                            try:
                                string_data = r2._execute_command(f'ps @ {hex(addr)}')
                                if string_data:
                                    strings.append({
                                        'address': hex(addr),
                                        'content': string_data.strip(),
                                        'reference_type': 'direct'
                                    })
                            except R2Exception:
                                continue
        except R2Exception:
            pass

        return strings

    def _analyze_control_flow(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze control flow from graph data."""
        flow_analysis = {
            'basic_blocks': 0,
            'edges': 0,
            'entry_points': 0,
            'exit_points': 0,
            'loops_detected': 0,
            'conditional_branches': 0
        }

        if not graph_data:
            return flow_analysis

        # Extract basic metrics from graph
        if isinstance(graph_data, list) and graph_data:
            blocks = graph_data[0].get('blocks', [])
            flow_analysis['basic_blocks'] = len(blocks)
            
            # Count edges and analyze structure
            total_edges = 0
            exit_points = 0
            
            for block in blocks:
                # Count outgoing edges
                jump = block.get('jump')
                fail = block.get('fail')
                
                if jump:
                    total_edges += 1
                if fail:
                    total_edges += 1
                    flow_analysis['conditional_branches'] += 1
                
                # Check for exit points (blocks with no outgoing edges)
                if not jump and not fail:
                    exit_points += 1
            
            flow_analysis['edges'] = total_edges
            flow_analysis['exit_points'] = exit_points
            flow_analysis['entry_points'] = 1  # Typically one entry point per function

        return flow_analysis

    def generate_license_bypass_suggestions(self, function_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate bypass suggestions based on decompilation analysis.
        
        Args:
            function_results: Results from decompile_function
            
        Returns:
            List of bypass suggestions
        """
        suggestions = []
        
        license_patterns = function_results.get('license_patterns', [])
        pseudocode = function_results.get('pseudocode', '')
        
        for pattern in license_patterns:
            if pattern['type'] == 'license_validation':
                line_content = pattern['line'].lower()
                
                # Suggest NOP patches for validation checks
                if 'if' in line_content and any(keyword in line_content for keyword in ['license', 'key', 'valid']):
                    suggestions.append({
                        'type': 'nop_patch',
                        'description': 'NOP out license validation check',
                        'line': pattern['line'],
                        'line_number': pattern['line_number'],
                        'confidence': 0.8,
                        'risk': 'low'
                    })
                
                # Suggest return value modification
                if 'return' in line_content:
                    suggestions.append({
                        'type': 'return_patch',
                        'description': 'Force return value to success',
                        'line': pattern['line'],
                        'line_number': pattern['line_number'],
                        'confidence': 0.9,
                        'risk': 'medium'
                    })
                
                # Suggest jump modification
                if any(jump in line_content for jump in ['jmp', 'je', 'jne', 'jz', 'jnz']):
                    suggestions.append({
                        'type': 'jump_patch',
                        'description': 'Modify conditional jump',
                        'line': pattern['line'],
                        'line_number': pattern['line_number'],
                        'confidence': 0.7,
                        'risk': 'medium'
                    })

        return suggestions

    def export_analysis_report(self, output_path: str, analysis_results: Dict[str, Any]) -> bool:
        """
        Export comprehensive analysis report.
        
        Args:
            output_path: Path to save report
            analysis_results: Analysis results to export
            
        Returns:
            Success status
        """
        try:
            report = {
                'binary_path': self.binary_path,
                'analysis_timestamp': analysis_results.get('timestamp'),
                'summary': {
                    'functions_analyzed': len(analysis_results),
                    'license_patterns_found': sum(len(r.get('license_patterns', [])) for r in analysis_results.values() if isinstance(r, dict)),
                    'vulnerabilities_found': sum(len(r.get('vulnerability_patterns', [])) for r in analysis_results.values() if isinstance(r, dict)),
                    'total_lines_decompiled': sum(r.get('complexity_metrics', {}).get('lines_of_code', 0) for r in analysis_results.values() if isinstance(r, dict))
                },
                'detailed_results': analysis_results
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Analysis report exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            return False


def analyze_binary_decompilation(binary_path: str, radare2_path: Optional[str] = None,
                                function_limit: Optional[int] = 20) -> Dict[str, Any]:
    """
    Perform comprehensive decompilation analysis of a binary.
    
    Args:
        binary_path: Path to binary file
        radare2_path: Optional path to radare2 executable
        function_limit: Maximum number of functions to analyze
        
    Returns:
        Complete decompilation analysis results
    """
    engine = R2DecompilationEngine(binary_path, radare2_path)
    return engine.decompile_all_functions(limit=function_limit)


__all__ = ['R2DecompilationEngine', 'analyze_binary_decompilation']