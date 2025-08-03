"""
Comprehensive Memory Analysis Integration

Main integration module that combines all memory dump analysis capabilities
including format detection, structure analysis, forensics, and reporting.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from ...utils.logger import get_logger
from .memory_dump_analyzer import (
    MemoryDumpAnalyzer, 
    MemoryDumpAnalysisResult,
    get_memory_dump_analyzer
)
from .memory_dump_formats import (
    MemoryDumpFormatDetector,
    DumpHeader,
    get_format_detector
)
from .memory_structure_analyzer import (
    MemoryCorruptionDetector,
    analyze_heap_structure,
    analyze_stack_structure,
    detect_memory_corruption
)
from .memory_forensics_engine import (
    MemoryForensicsEngine,
    MemoryAnalysisResult,
    get_memory_forensics_engine
)

logger = get_logger(__name__)


class ComprehensiveMemoryAnalyzer:
    """
    Main comprehensive memory analysis system that integrates all components
    """
    
    def __init__(self, cache_directory: Optional[str] = None):
        """Initialize the comprehensive memory analyzer"""
        self.logger = logger.getChild("ComprehensiveAnalyzer")
        
        # Initialize components
        self.dump_analyzer = get_memory_dump_analyzer()
        self.format_detector = get_format_detector()
        self.forensics_engine = get_memory_forensics_engine()
        self.corruption_detector = MemoryCorruptionDetector()
        
        # Cache directory
        if cache_directory:
            self.cache_directory = Path(cache_directory)
        else:
            self.cache_directory = Path("./cache/comprehensive_memory")
        
        self.cache_directory.mkdir(parents=True, exist_ok=True)
        
        # Analysis history
        self.analysis_history: List[Dict[str, Any]] = []
        
    def analyze_memory_dump_comprehensive(
        self,
        dump_path: Union[str, Path],
        analysis_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive memory dump analysis using all available techniques
        
        Args:
            dump_path: Path to the memory dump file
            analysis_options: Optional analysis configuration
            
        Returns:
            Comprehensive analysis results
        """
        start_time = time.time()
        dump_path = str(dump_path)
        
        # Default analysis options
        if analysis_options is None:
            analysis_options = {
                'deep_analysis': True,
                'include_disassembly': True,
                'extract_artifacts': True,
                'detect_corruption': True,
                'analyze_structures': True,
                'generate_reports': True,
                'export_formats': ['json', 'html'],
                'max_analysis_time': 3600  # 1 hour max
            }
        
        self.logger.info(f"Starting comprehensive memory dump analysis: {dump_path}")
        
        # Initialize result structure
        result = {
            'metadata': {
                'dump_path': dump_path,
                'analysis_start_time': start_time,
                'analysis_options': analysis_options,
                'components_used': []
            },
            'format_detection': {},
            'basic_forensics': {},
            'detailed_analysis': {},
            'structure_analysis': {},
            'corruption_analysis': {},
            'security_assessment': {},
            'performance_metrics': {},
            'reports_generated': [],
            'errors': [],
            'warnings': []
        }
        
        try:
            # Step 1: Format detection and validation
            self.logger.info("Step 1: Detecting memory dump format")
            result['format_detection'] = self._perform_format_detection(dump_path)
            result['metadata']['components_used'].append('format_detector')
            
            # Step 2: Basic memory forensics using existing engine
            if self.forensics_engine:
                self.logger.info("Step 2: Performing basic memory forensics")
                result['basic_forensics'] = self._perform_basic_forensics(
                    dump_path, analysis_options.get('deep_analysis', True)
                )
                result['metadata']['components_used'].append('forensics_engine')
            
            # Step 3: Detailed memory dump analysis
            if self.dump_analyzer:
                self.logger.info("Step 3: Performing detailed memory analysis")
                result['detailed_analysis'] = self._perform_detailed_analysis(
                    dump_path, analysis_options
                )
                result['metadata']['components_used'].append('dump_analyzer')
            
            # Step 4: Memory structure analysis
            if analysis_options.get('analyze_structures', True):
                self.logger.info("Step 4: Analyzing memory structures")
                result['structure_analysis'] = self._perform_structure_analysis(
                    dump_path, result['format_detection']
                )
                result['metadata']['components_used'].append('structure_analyzer')
            
            # Step 5: Corruption detection
            if analysis_options.get('detect_corruption', True):
                self.logger.info("Step 5: Detecting memory corruption")
                result['corruption_analysis'] = self._perform_corruption_analysis(
                    dump_path, result['detailed_analysis']
                )
                result['metadata']['components_used'].append('corruption_detector')
            
            # Step 6: Security assessment
            self.logger.info("Step 6: Performing security assessment")
            result['security_assessment'] = self._perform_security_assessment(result)
            
            # Step 7: Generate reports
            if analysis_options.get('generate_reports', True):
                self.logger.info("Step 7: Generating analysis reports")
                result['reports_generated'] = self._generate_reports(
                    result, analysis_options.get('export_formats', ['json'])
                )
            
            # Calculate performance metrics
            end_time = time.time()
            result['performance_metrics'] = {
                'total_analysis_time': end_time - start_time,
                'analysis_completed': True,
                'components_successful': len(result['metadata']['components_used']),
                'errors_encountered': len(result['errors']),
                'warnings_issued': len(result['warnings'])
            }
            
            # Add to analysis history
            self.analysis_history.append({
                'timestamp': start_time,
                'dump_path': dump_path,
                'success': True,
                'duration': end_time - start_time,
                'components_used': result['metadata']['components_used']
            })
            
            self.logger.info(
                f"Comprehensive analysis completed in {end_time - start_time:.2f}s "
                f"with {len(result['metadata']['components_used'])} components"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Comprehensive analysis failed: {e}")
            
            end_time = time.time()
            result['errors'].append(str(e))
            result['performance_metrics'] = {
                'total_analysis_time': end_time - start_time,
                'analysis_completed': False,
                'analysis_failed': True,
                'error': str(e)
            }
            
            # Add failed analysis to history
            self.analysis_history.append({
                'timestamp': start_time,
                'dump_path': dump_path,
                'success': False,
                'duration': end_time - start_time,
                'error': str(e)
            })
            
            return result
    
    def _perform_format_detection(self, dump_path: str) -> Dict[str, Any]:
        """Perform memory dump format detection and validation"""
        try:
            # Detect format
            header = self.format_detector.detect_format(dump_path)
            
            # Validate integrity
            validation = self.format_detector.validate_dump_integrity(dump_path, header)
            
            return {
                'format_detected': header.format_type.value,
                'architecture': header.architecture,
                'page_size': header.page_size,
                'total_pages': header.total_pages,
                'compressed': header.compressed,
                'encrypted': header.encryption,
                'timestamp': header.timestamp,
                'version': header.version,
                'metadata': header.metadata,
                'validation': validation,
                'supported_formats': self.format_detector.get_supported_formats()
            }
            
        except Exception as e:
            self.logger.error(f"Format detection failed: {e}")
            return {
                'error': str(e),
                'format_detected': 'unknown'
            }
    
    def _perform_basic_forensics(self, dump_path: str, deep_analysis: bool) -> Dict[str, Any]:
        """Perform basic memory forensics analysis"""
        try:
            # Run memory forensics analysis
            forensics_result = self.forensics_engine.analyze_memory_dump(
                dump_path, deep_analysis=deep_analysis
            )
            
            # Convert to serializable format
            return {
                'dump_path': forensics_result.dump_path,
                'analysis_profile': forensics_result.analysis_profile,
                'total_processes': len(forensics_result.processes),
                'total_modules': len(forensics_result.modules),
                'network_connections': len(forensics_result.network_connections),
                'security_findings': len(forensics_result.security_findings),
                'has_suspicious_activity': forensics_result.has_suspicious_activity,
                'hidden_process_count': forensics_result.hidden_process_count,
                'analysis_time': forensics_result.analysis_time,
                'artifacts_found': forensics_result.artifacts_found,
                'error': forensics_result.error,
                
                # Detailed results (limited for serialization)
                'processes_summary': [
                    {
                        'pid': proc.pid,
                        'name': proc.name,
                        'is_hidden': proc.is_hidden,
                        'suspicious_indicators': proc.suspicious_indicators
                    }
                    for proc in forensics_result.processes[:50]  # Limit for performance
                ],
                'modules_summary': [
                    {
                        'name': mod.name,
                        'base_address': hex(mod.base_address),
                        'is_suspicious': mod.is_suspicious
                    }
                    for mod in forensics_result.modules[:50]  # Limit for performance
                ],
                'security_findings_summary': forensics_result.security_findings
            }
            
        except Exception as e:
            self.logger.error(f"Basic forensics analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_completed': False
            }
    
    def _perform_detailed_analysis(
        self, 
        dump_path: str, 
        analysis_options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform detailed memory dump analysis"""
        try:
            # Run comprehensive dump analysis
            detailed_result = self.dump_analyzer.analyze_memory_dump(
                dump_path,
                deep_analysis=analysis_options.get('deep_analysis', True),
                include_disassembly=analysis_options.get('include_disassembly', True),
                extract_artifacts=analysis_options.get('extract_artifacts', True)
            )
            
            # Convert to serializable format
            return {
                'dump_format': detailed_result.dump_format.value,
                'architecture': detailed_result.architecture.value,
                'dump_size': detailed_result.dump_size,
                'analysis_duration': detailed_result.analysis_duration,
                'confidence_score': detailed_result.confidence_score,
                'security_risk_score': detailed_result.security_risk_score,
                
                # Process analysis
                'processes_analyzed': len(detailed_result.processes),
                'memory_regions_found': len(detailed_result.memory_regions),
                'code_injections_detected': len(detailed_result.code_injections),
                'heap_analyses_performed': len(detailed_result.heap_analyses),
                'stack_analyses_performed': len(detailed_result.stack_analyses),
                
                # Artifact extraction
                'total_strings_extracted': len(detailed_result.extracted_strings),
                'crypto_artifacts': len(detailed_result.crypto_artifacts),
                'network_artifacts': len(detailed_result.network_artifacts),
                'file_artifacts': len(detailed_result.file_artifacts),
                'registry_artifacts': len(detailed_result.registry_artifacts),
                
                # Security analysis
                'exploit_signatures_found': len(detailed_result.exploit_signatures),
                'anti_analysis_techniques': len(detailed_result.anti_analysis_techniques),
                'behavioral_artifacts': len(detailed_result.behavioral_artifacts),
                
                # Detailed summaries (limited)
                'code_injections_summary': [
                    {
                        'injection_type': inj.injection_type,
                        'target_process': inj.target_process,
                        'severity_score': inj.severity_score,
                        'shellcode_detected': inj.shellcode_detected
                    }
                    for inj in detailed_result.code_injections
                ],
                'memory_regions_summary': [
                    {
                        'start_address': hex(region.start_address),
                        'size': region.size,
                        'type': region.region_type.value,
                        'has_shellcode_characteristics': region.has_shellcode_characteristics,
                        'patterns_found_count': len(region.patterns_found)
                    }
                    for region in detailed_result.memory_regions[:100]  # Limit
                ],
                'security_findings': {
                    'exploit_signatures': detailed_result.exploit_signatures[:20],  # Limit
                    'anti_analysis_techniques': detailed_result.anti_analysis_techniques[:20],
                    'behavioral_artifacts': detailed_result.behavioral_artifacts[:20]
                },
                
                'error_messages': detailed_result.error_messages
            }
            
        except Exception as e:
            self.logger.error(f"Detailed analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_completed': False
            }
    
    def _perform_structure_analysis(
        self, 
        dump_path: str, 
        format_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform memory structure analysis"""
        try:
            structure_results = {
                'heap_analysis': [],
                'stack_analysis': [],
                'corruption_patterns': [],
                'analysis_summary': {}
            }
            
            # Read memory dump in chunks for structure analysis
            chunk_size = 1024 * 1024  # 1MB chunks
            architecture = format_info.get('architecture', 'x86_64')
            
            with open(dump_path, 'rb') as f:
                file_size = f.seek(0, 2)
                f.seek(0)
                
                heap_regions_analyzed = 0
                stack_regions_analyzed = 0
                total_corruptions = 0
                
                for offset in range(0, min(file_size, 100 * chunk_size), chunk_size):
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Analyze as potential heap
                    try:
                        heap_arena = analyze_heap_structure(
                            chunk, offset, "auto"
                        )
                        
                        if heap_arena.chunks:
                            heap_regions_analyzed += 1
                            structure_results['heap_analysis'].append({
                                'base_address': hex(heap_arena.base_address),
                                'heap_type': heap_arena.heap_type.value,
                                'total_chunks': len(heap_arena.chunks),
                                'corruption_score': heap_arena.corruption_score,
                                'corrupted_chunks': len([c for c in heap_arena.chunks if c.is_corrupted])
                            })
                    except Exception as e:
                        self.logger.debug(f"Heap analysis failed for chunk at {offset}: {e}")
                    
                    # Analyze as potential stack
                    try:
                        call_chain = analyze_stack_structure(
                            chunk, offset, offset, architecture
                        )
                        
                        if call_chain.frames:
                            stack_regions_analyzed += 1
                            structure_results['stack_analysis'].append({
                                'base_address': hex(offset),
                                'total_frames': len(call_chain.frames),
                                'corruption_detected': call_chain.corruption_detected,
                                'rop_chain_detected': call_chain.rop_chain_detected,
                                'gadgets_found': len(call_chain.gadgets_found)
                            })
                    except Exception as e:
                        self.logger.debug(f"Stack analysis failed for chunk at {offset}: {e}")
                    
                    # Detect generic corruption
                    try:
                        corruptions = detect_memory_corruption(
                            chunk, offset, "unknown", architecture
                        )
                        
                        total_corruptions += len(corruptions)
                        for corruption in corruptions:
                            structure_results['corruption_patterns'].append({
                                'type': corruption.corruption_type,
                                'address': hex(corruption.address),
                                'severity': corruption.severity,
                                'description': corruption.description,
                                'exploitability': corruption.exploitability
                            })
                    except Exception as e:
                        self.logger.debug(f"Corruption detection failed for chunk at {offset}: {e}")
                    
                    # Limit analysis to prevent excessive runtime
                    if heap_regions_analyzed + stack_regions_analyzed > 50:
                        break
            
            structure_results['analysis_summary'] = {
                'heap_regions_analyzed': heap_regions_analyzed,
                'stack_regions_analyzed': stack_regions_analyzed,
                'total_corruptions_found': total_corruptions,
                'analysis_limited': heap_regions_analyzed + stack_regions_analyzed >= 50
            }
            
            return structure_results
            
        except Exception as e:
            self.logger.error(f"Structure analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_completed': False
            }
    
    def _perform_corruption_analysis(
        self, 
        dump_path: str, 
        detailed_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive corruption analysis"""
        try:
            corruption_results = {
                'corruption_summary': {
                    'total_corruptions': 0,
                    'critical_corruptions': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0
                },
                'exploitation_assessment': {
                    'exploitable_vulnerabilities': 0,
                    'potential_exploits': [],
                    'mitigation_bypasses': []
                },
                'corruption_types': {},
                'detailed_findings': []
            }
            
            # Analyze corruption from detailed analysis results
            if 'code_injections_summary' in detailed_analysis:
                for injection in detailed_analysis['code_injections_summary']:
                    corruption_results['corruption_summary']['total_corruptions'] += 1
                    
                    if injection.get('severity_score', 0) > 7:
                        corruption_results['corruption_summary']['critical_corruptions'] += 1
                    elif injection.get('severity_score', 0) > 5:
                        corruption_results['corruption_summary']['high_severity'] += 1
                    
                    if injection.get('shellcode_detected', False):
                        corruption_results['exploitation_assessment']['exploitable_vulnerabilities'] += 1
                        corruption_results['exploitation_assessment']['potential_exploits'].append({
                            'type': 'code_injection',
                            'target': injection.get('target_process', 'unknown'),
                            'technique': injection.get('injection_type', 'unknown')
                        })
            
            # Analyze heap corruptions
            heap_corruptions = 0
            if detailed_analysis.get('heap_analyses_performed', 0) > 0:
                # Count heap-related corruptions from security findings
                security_findings = detailed_analysis.get('security_findings', {})
                for finding_type, findings in security_findings.items():
                    for finding in findings:
                        if 'heap' in str(finding).lower():
                            heap_corruptions += 1
            
            corruption_results['corruption_types']['heap_corruption'] = heap_corruptions
            
            # Analyze stack corruptions
            stack_corruptions = 0
            if detailed_analysis.get('stack_analyses_performed', 0) > 0:
                # Count stack-related corruptions
                security_findings = detailed_analysis.get('security_findings', {})
                for finding_type, findings in security_findings.items():
                    for finding in findings:
                        if any(term in str(finding).lower() for term in ['stack', 'rop', 'overflow']):
                            stack_corruptions += 1
            
            corruption_results['corruption_types']['stack_corruption'] = stack_corruptions
            
            # Calculate overall corruption assessment
            total_corruptions = (
                corruption_results['corruption_summary']['total_corruptions'] +
                heap_corruptions + stack_corruptions
            )
            
            corruption_results['corruption_summary']['total_corruptions'] = total_corruptions
            
            # Assess exploitation potential
            exploitability_score = 0.0
            if corruption_results['exploitation_assessment']['exploitable_vulnerabilities'] > 0:
                exploitability_score += 4.0
            
            if corruption_results['corruption_summary']['critical_corruptions'] > 0:
                exploitability_score += 3.0
            
            if stack_corruptions > 0:
                exploitability_score += 2.0
                
            if heap_corruptions > 0:
                exploitability_score += 1.5
            
            corruption_results['exploitation_assessment']['exploitability_score'] = min(exploitability_score, 10.0)
            
            return corruption_results
            
        except Exception as e:
            self.logger.error(f"Corruption analysis failed: {e}")
            return {
                'error': str(e),
                'analysis_completed': False
            }
    
    def _perform_security_assessment(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive security assessment"""
        try:
            security_assessment = {
                'overall_risk_score': 0.0,
                'threat_level': 'low',
                'key_findings': [],
                'recommendations': [],
                'attack_vectors': [],
                'defensive_measures': []
            }
            
            # Calculate overall risk score from all components
            risk_factors = []
            
            # Format detection risks
            format_info = analysis_result.get('format_detection', {})
            if format_info.get('validation', {}).get('valid', True) is False:
                risk_factors.append(2.0)
                security_assessment['key_findings'].append("Invalid or corrupted dump format detected")
            
            # Basic forensics risks
            basic_forensics = analysis_result.get('basic_forensics', {})
            if basic_forensics.get('has_suspicious_activity', False):
                risk_factors.append(3.0)
                security_assessment['key_findings'].append("Suspicious activity detected in memory")
            
            if basic_forensics.get('hidden_process_count', 0) > 0:
                risk_factors.append(4.0)
                security_assessment['key_findings'].append(
                    f"Hidden processes detected: {basic_forensics['hidden_process_count']}"
                )
            
            # Detailed analysis risks
            detailed_analysis = analysis_result.get('detailed_analysis', {})
            security_risk_score = detailed_analysis.get('security_risk_score', 0)
            if security_risk_score > 0:
                risk_factors.append(security_risk_score)
            
            if detailed_analysis.get('code_injections_detected', 0) > 0:
                risk_factors.append(5.0)
                security_assessment['key_findings'].append("Code injection detected")
                security_assessment['attack_vectors'].append({
                    'vector': 'code_injection',
                    'severity': 'high',
                    'description': 'Malicious code injection detected in process memory'
                })
            
            # Corruption analysis risks
            corruption_analysis = analysis_result.get('corruption_analysis', {})
            corruption_score = corruption_analysis.get('corruption_summary', {}).get('total_corruptions', 0)
            if corruption_score > 0:
                risk_factors.append(min(corruption_score * 0.5, 5.0))
            
            exploitability_score = corruption_analysis.get('exploitation_assessment', {}).get('exploitability_score', 0)
            if exploitability_score > 0:
                risk_factors.append(exploitability_score)
                security_assessment['attack_vectors'].append({
                    'vector': 'memory_corruption_exploit',
                    'severity': 'high' if exploitability_score > 6 else 'medium',
                    'description': 'Memory corruption vulnerabilities that could be exploited'
                })
            
            # Calculate overall risk score
            if risk_factors:
                security_assessment['overall_risk_score'] = min(sum(risk_factors) / len(risk_factors), 10.0)
            
            # Determine threat level
            if security_assessment['overall_risk_score'] >= 8.0:
                security_assessment['threat_level'] = 'critical'
            elif security_assessment['overall_risk_score'] >= 6.0:
                security_assessment['threat_level'] = 'high'
            elif security_assessment['overall_risk_score'] >= 4.0:
                security_assessment['threat_level'] = 'medium'
            else:
                security_assessment['threat_level'] = 'low'
            
            # Generate recommendations based on findings
            security_assessment['recommendations'] = self._generate_security_recommendations(
                security_assessment, analysis_result
            )
            
            return security_assessment
            
        except Exception as e:
            self.logger.error(f"Security assessment failed: {e}")
            return {
                'error': str(e),
                'overall_risk_score': 0.0,
                'threat_level': 'unknown'
            }
    
    def _generate_security_recommendations(
        self, 
        security_assessment: Dict[str, Any], 
        analysis_result: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations based on analysis results"""
        recommendations = []
        
        try:
            threat_level = security_assessment.get('threat_level', 'low')
            
            if threat_level in ['critical', 'high']:
                recommendations.extend([
                    "Immediate incident response required",
                    "Isolate affected systems from network",
                    "Perform full malware scan and removal",
                    "Review and update security controls"
                ])
            
            # Code injection recommendations
            if analysis_result.get('detailed_analysis', {}).get('code_injections_detected', 0) > 0:
                recommendations.extend([
                    "Implement or strengthen DEP/NX protections",
                    "Enable ASLR (Address Space Layout Randomization)",
                    "Deploy Control Flow Integrity (CFI) if available",
                    "Review application input validation"
                ])
            
            # Memory corruption recommendations
            corruption_analysis = analysis_result.get('corruption_analysis', {})
            if corruption_analysis.get('corruption_summary', {}).get('total_corruptions', 0) > 0:
                recommendations.extend([
                    "Enable heap protection mechanisms",
                    "Implement stack canaries/guards",
                    "Use memory-safe programming languages where possible",
                    "Perform regular security code reviews"
                ])
            
            # Hidden process recommendations
            if analysis_result.get('basic_forensics', {}).get('hidden_process_count', 0) > 0:
                recommendations.extend([
                    "Deploy advanced endpoint detection and response (EDR)",
                    "Implement process integrity monitoring",
                    "Review and harden system configurations",
                    "Conduct thorough rootkit scan"
                ])
            
            # Generic security hardening
            recommendations.extend([
                "Keep all software and operating systems updated",
                "Implement principle of least privilege",
                "Enable comprehensive logging and monitoring",
                "Conduct regular security assessments"
            ])
            
            return list(set(recommendations))  # Remove duplicates
            
        except Exception as e:
            self.logger.debug(f"Recommendation generation failed: {e}")
            return ["Conduct thorough security review based on analysis findings"]
    
    def _generate_reports(
        self, 
        analysis_result: Dict[str, Any], 
        export_formats: List[str]
    ) -> List[str]:
        """Generate analysis reports in various formats"""
        generated_reports = []
        
        try:
            timestamp = int(time.time())
            base_filename = f"memory_analysis_{timestamp}"
            
            for format_type in export_formats:
                try:
                    if format_type.lower() == 'json':
                        report_path = self.cache_directory / f"{base_filename}.json"
                        self._generate_json_report(analysis_result, str(report_path))
                        generated_reports.append(str(report_path))
                    
                    elif format_type.lower() == 'html':
                        report_path = self.cache_directory / f"{base_filename}.html"
                        self._generate_html_report(analysis_result, str(report_path))
                        generated_reports.append(str(report_path))
                    
                    elif format_type.lower() == 'txt':
                        report_path = self.cache_directory / f"{base_filename}.txt"
                        self._generate_text_report(analysis_result, str(report_path))
                        generated_reports.append(str(report_path))
                    
                except Exception as e:
                    self.logger.error(f"Failed to generate {format_type} report: {e}")
            
            return generated_reports
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return []
    
    def _generate_json_report(self, analysis_result: Dict[str, Any], output_path: str):
        """Generate JSON format report"""
        try:
            with open(output_path, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            
            self.logger.info(f"JSON report generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"JSON report generation failed: {e}")
    
    def _generate_html_report(self, analysis_result: Dict[str, Any], output_path: str):
        """Generate HTML format report"""
        try:
            # Extract key metrics
            metadata = analysis_result.get('metadata', {})
            security_assessment = analysis_result.get('security_assessment', {})
            performance_metrics = analysis_result.get('performance_metrics', {})
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Memory Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; margin: -20px -20px 20px -20px; }}
        .section {{ margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .critical {{ background-color: #ffebee; border-left: 5px solid #f44336; }}
        .warning {{ background-color: #fff3e0; border-left: 5px solid #ff9800; }}
        .info {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; }}
        .success {{ background-color: #e8f5e8; border-left: 5px solid #4caf50; }}
        .metric {{ font-size: 28px; font-weight: bold; color: #2c3e50; text-align: center; }}
        .score-critical {{ color: #d32f2f; }}
        .score-high {{ color: #f57c00; }}
        .score-medium {{ color: #fbc02d; }}
        .score-low {{ color: #388e3c; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold; text-transform: uppercase; }}
        .badge-critical {{ background-color: #ffcdd2; color: #d32f2f; }}
        .badge-high {{ background-color: #ffe0b2; color: #f57c00; }}
        .badge-medium {{ background-color: #fff9c4; color: #fbc02d; }}
        .badge-low {{ background-color: #c8e6c9; color: #388e3c; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Comprehensive Memory Analysis Report</h1>
            <p>Generated on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</p>
            <p>Analysis Duration: {performance_metrics.get('total_analysis_time', 0):.2f} seconds</p>
        </div>
        
        <div class="section {('critical' if security_assessment.get('threat_level') in ['critical', 'high'] else 'warning' if security_assessment.get('threat_level') == 'medium' else 'success')}">
            <h2>🛡️ Security Assessment</h2>
            <div class="grid">
                <div class="card">
                    <h3>Overall Risk Score</h3>
                    <div class="metric score-{('critical' if security_assessment.get('overall_risk_score', 0) >= 8 else 'high' if security_assessment.get('overall_risk_score', 0) >= 6 else 'medium' if security_assessment.get('overall_risk_score', 0) >= 4 else 'low')}">{security_assessment.get('overall_risk_score', 0):.1f}/10.0</div>
                </div>
                <div class="card">
                    <h3>Threat Level</h3>
                    <span class="badge badge-{security_assessment.get('threat_level', 'low')}">{security_assessment.get('threat_level', 'unknown').upper()}</span>
                </div>
            </div>
        </div>
        
        <div class="section info">
            <h2>📊 Analysis Overview</h2>
            <table>
                <tr><td><strong>Dump Path:</strong></td><td>{metadata.get('dump_path', 'N/A')}</td></tr>
                <tr><td><strong>Components Used:</strong></td><td>{', '.join(metadata.get('components_used', []))}</td></tr>
                <tr><td><strong>Analysis Completed:</strong></td><td>{'✅ Yes' if performance_metrics.get('analysis_completed', False) else '❌ No'}</td></tr>
                <tr><td><strong>Errors Encountered:</strong></td><td>{performance_metrics.get('errors_encountered', 0)}</td></tr>
            </table>
        </div>
"""
            
            # Add format detection section
            format_detection = analysis_result.get('format_detection', {})
            if format_detection:
                html_content += f"""
        <div class="section">
            <h2>🗂️ Format Detection</h2>
            <table>
                <tr><td><strong>Format:</strong></td><td>{format_detection.get('format_detected', 'Unknown')}</td></tr>
                <tr><td><strong>Architecture:</strong></td><td>{format_detection.get('architecture', 'Unknown')}</td></tr>
                <tr><td><strong>Page Size:</strong></td><td>{format_detection.get('page_size', 0):,} bytes</td></tr>
                <tr><td><strong>Total Pages:</strong></td><td>{format_detection.get('total_pages', 0):,}</td></tr>
                <tr><td><strong>Compressed:</strong></td><td>{'Yes' if format_detection.get('compressed', False) else 'No'}</td></tr>
            </table>
        </div>
"""
            
            # Add key findings
            key_findings = security_assessment.get('key_findings', [])
            if key_findings:
                html_content += """
        <div class="section warning">
            <h2>⚠️ Key Security Findings</h2>
            <ul>
"""
                for finding in key_findings:
                    html_content += f"<li>{finding}</li>"
                
                html_content += """
            </ul>
        </div>
"""
            
            # Add recommendations
            recommendations = security_assessment.get('recommendations', [])
            if recommendations:
                html_content += """
        <div class="section info">
            <h2>💡 Security Recommendations</h2>
            <ul>
"""
                for recommendation in recommendations:
                    html_content += f"<li>{recommendation}</li>"
                
                html_content += """
            </ul>
        </div>
"""
            
            html_content += """
        <div class="section">
            <h2>📈 Component Analysis Summary</h2>
            <div class="grid">
"""
            
            # Add component summaries
            basic_forensics = analysis_result.get('basic_forensics', {})
            if basic_forensics:
                html_content += f"""
                <div class="card">
                    <h3>Memory Forensics</h3>
                    <p><strong>Processes:</strong> {basic_forensics.get('total_processes', 0)}</p>
                    <p><strong>Modules:</strong> {basic_forensics.get('total_modules', 0)}</p>
                    <p><strong>Network Connections:</strong> {basic_forensics.get('network_connections', 0)}</p>
                    <p><strong>Security Findings:</strong> {basic_forensics.get('security_findings', 0)}</p>
                </div>
"""
            
            detailed_analysis = analysis_result.get('detailed_analysis', {})
            if detailed_analysis:
                html_content += f"""
                <div class="card">
                    <h3>Detailed Analysis</h3>
                    <p><strong>Memory Regions:</strong> {detailed_analysis.get('memory_regions_found', 0)}</p>
                    <p><strong>Code Injections:</strong> {detailed_analysis.get('code_injections_detected', 0)}</p>
                    <p><strong>Strings Extracted:</strong> {detailed_analysis.get('total_strings_extracted', 0):,}</p>
                    <p><strong>Confidence Score:</strong> {detailed_analysis.get('confidence_score', 0):.1f}/10.0</p>
                </div>
"""
            
            corruption_analysis = analysis_result.get('corruption_analysis', {})
            if corruption_analysis:
                corruption_summary = corruption_analysis.get('corruption_summary', {})
                html_content += f"""
                <div class="card">
                    <h3>Corruption Analysis</h3>
                    <p><strong>Total Corruptions:</strong> {corruption_summary.get('total_corruptions', 0)}</p>
                    <p><strong>Critical:</strong> {corruption_summary.get('critical_corruptions', 0)}</p>
                    <p><strong>High Severity:</strong> {corruption_summary.get('high_severity', 0)}</p>
                    <p><strong>Exploitability Score:</strong> {corruption_analysis.get('exploitation_assessment', {}).get('exploitability_score', 0):.1f}/10.0</p>
                </div>
"""
            
            html_content += """
            </div>
        </div>
        
        <div class="section">
            <h2>ℹ️ Report Information</h2>
            <p>This comprehensive report was generated by the Intellicrack Memory Analysis System.</p>
            <p>The analysis combines multiple engines including format detection, memory forensics, structure analysis, and corruption detection.</p>
            <p>For detailed technical data, please refer to the JSON export of this analysis.</p>
        </div>
    </div>
</body>
</html>
"""
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"HTML report generation failed: {e}")
    
    def _generate_text_report(self, analysis_result: Dict[str, Any], output_path: str):
        """Generate text format report"""
        try:
            with open(output_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("COMPREHENSIVE MEMORY ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Metadata
                metadata = analysis_result.get('metadata', {})
                f.write("ANALYSIS METADATA\n")
                f.write("-" * 40 + "\n")
                f.write(f"Dump Path: {metadata.get('dump_path', 'N/A')}\n")
                f.write(f"Analysis Start: {time.ctime(metadata.get('analysis_start_time', 0))}\n")
                f.write(f"Components Used: {', '.join(metadata.get('components_used', []))}\n")
                
                # Performance metrics
                performance = analysis_result.get('performance_metrics', {})
                f.write(f"Analysis Duration: {performance.get('total_analysis_time', 0):.2f} seconds\n")
                f.write(f"Analysis Completed: {'Yes' if performance.get('analysis_completed', False) else 'No'}\n\n")
                
                # Security assessment
                security = analysis_result.get('security_assessment', {})
                f.write("SECURITY ASSESSMENT\n")
                f.write("-" * 40 + "\n")
                f.write(f"Overall Risk Score: {security.get('overall_risk_score', 0):.1f}/10.0\n")
                f.write(f"Threat Level: {security.get('threat_level', 'unknown').upper()}\n\n")
                
                # Key findings
                key_findings = security.get('key_findings', [])
                if key_findings:
                    f.write("KEY SECURITY FINDINGS\n")
                    f.write("-" * 40 + "\n")
                    for finding in key_findings:
                        f.write(f"• {finding}\n")
                    f.write("\n")
                
                # Recommendations
                recommendations = security.get('recommendations', [])
                if recommendations:
                    f.write("SECURITY RECOMMENDATIONS\n")
                    f.write("-" * 40 + "\n")
                    for rec in recommendations:
                        f.write(f"• {rec}\n")
                    f.write("\n")
                
                # Component summaries
                f.write("COMPONENT ANALYSIS SUMMARY\n")
                f.write("-" * 40 + "\n")
                
                basic_forensics = analysis_result.get('basic_forensics', {})
                if basic_forensics:
                    f.write(f"Memory Forensics - Processes: {basic_forensics.get('total_processes', 0)}, ")
                    f.write(f"Modules: {basic_forensics.get('total_modules', 0)}, ")
                    f.write(f"Security Findings: {basic_forensics.get('security_findings', 0)}\n")
                
                detailed_analysis = analysis_result.get('detailed_analysis', {})
                if detailed_analysis:
                    f.write(f"Detailed Analysis - Memory Regions: {detailed_analysis.get('memory_regions_found', 0)}, ")
                    f.write(f"Code Injections: {detailed_analysis.get('code_injections_detected', 0)}, ")
                    f.write(f"Strings: {detailed_analysis.get('total_strings_extracted', 0):,}\n")
                
                corruption_analysis = analysis_result.get('corruption_analysis', {})
                if corruption_analysis:
                    corruption_summary = corruption_analysis.get('corruption_summary', {})
                    f.write(f"Corruption Analysis - Total Corruptions: {corruption_summary.get('total_corruptions', 0)}, ")
                    f.write(f"Critical: {corruption_summary.get('critical_corruptions', 0)}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("End of Report\n")
            
            self.logger.info(f"Text report generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Text report generation failed: {e}")
    
    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get analysis history"""
        return self.analysis_history.copy()
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get analyzer capabilities and status"""
        return {
            'components_available': {
                'dump_analyzer': self.dump_analyzer is not None,
                'format_detector': self.format_detector is not None,
                'forensics_engine': self.forensics_engine is not None,
                'corruption_detector': self.corruption_detector is not None
            },
            'supported_formats': self.format_detector.get_supported_formats() if self.format_detector else [],
            'cache_directory': str(self.cache_directory),
            'analysis_history_count': len(self.analysis_history)
        }


# Singleton instance
_comprehensive_analyzer: Optional[ComprehensiveMemoryAnalyzer] = None


def get_comprehensive_memory_analyzer() -> Optional[ComprehensiveMemoryAnalyzer]:
    """Get or create the comprehensive memory analyzer singleton"""
    global _comprehensive_analyzer
    if _comprehensive_analyzer is None:
        try:
            _comprehensive_analyzer = ComprehensiveMemoryAnalyzer()
        except Exception as e:
            logger.error(f"Failed to initialize comprehensive memory analyzer: {e}")
            return None
    return _comprehensive_analyzer


def analyze_memory_dump_complete(
    dump_path: str,
    analysis_options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Quick comprehensive memory dump analysis function for integration
    
    Args:
        dump_path: Path to the memory dump file
        analysis_options: Optional analysis configuration
        
    Returns:
        Complete analysis results
    """
    analyzer = get_comprehensive_memory_analyzer()
    if analyzer:
        return analyzer.analyze_memory_dump_comprehensive(dump_path, analysis_options)
    
    return {
        'error': 'Comprehensive memory analyzer not available',
        'metadata': {'dump_path': dump_path},
        'performance_metrics': {'analysis_completed': False}
    }