"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
API Trace Reporting and Visualization Engine

This module provides comprehensive reporting and visualization capabilities
for API call tracing data, including timeline visualizations, pattern analysis
reports, and bypass strategy recommendations.

Features:
- API call timeline visualization
- Call frequency and pattern analysis
- License validation sequence reports
- Protection mechanism identification
- Bypass strategy recommendations
- Interactive HTML reports
- Export to multiple formats
- Statistical analysis
"""

import json
import logging
import statistics
import time
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import base64
import io

from ..analysis.api_call_tracer import APICall, APICategory, CallDirection
from ..analysis.api_pattern_analyzer import DetectedPattern, PatternType, PatternSeverity
from ..analysis.call_stack_analyzer import CallChain, StackAnomaly, CallChainPattern
from ..analysis.realtime_api_correlator import CorrelationEvent, CorrelationEventType

logger = logging.getLogger(__name__)


class ReportFormat(str):
    """Supported report formats."""
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    XML = "xml"


class APITraceReporter:
    """
    Comprehensive API trace reporting and visualization engine.
    
    Generates detailed reports with visualizations, analysis, and
    recommendations based on API call tracing data.
    """
    
    def __init__(self):
        """Initialize the API trace reporter."""
        self.report_templates = self._load_report_templates()
        logger.info("API Trace Reporter initialized")
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load HTML report templates."""
        return {
            'main': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Trace Analysis Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; border-left: 4px solid #007bff; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { color: #6c757d; font-size: 14px; }
        .chart-container { height: 400px; margin: 20px 0; }
        .pattern-item { padding: 10px; margin: 5px 0; border-radius: 5px; border-left: 4px solid; }
        .pattern-critical { border-left-color: #dc3545; background-color: #fff5f5; }
        .pattern-high { border-left-color: #fd7e14; background-color: #fff8f0; }
        .pattern-medium { border-left-color: #ffc107; background-color: #fffdf0; }
        .pattern-low { border-left-color: #28a745; background-color: #f8fff8; }
        .call-stack { font-family: monospace; font-size: 12px; background: #f8f9fa; padding: 10px; border-radius: 5px; }
        .recommendation { background: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 10px 0; border-radius: 5px; }
        .api-call { font-family: monospace; color: #495057; }
        .timestamp { color: #6c757d; font-size: 12px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; }
        .tabs { margin: 20px 0; }
        .tab-button { background: #f8f9fa; border: 1px solid #dee2e6; padding: 10px 20px; margin-right: 5px; cursor: pointer; }
        .tab-button.active { background: #007bff; color: white; }
        .tab-content { display: none; padding: 20px; border: 1px solid #dee2e6; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 API Trace Analysis Report</h1>
        <p>Generated on {timestamp} | Analysis Period: {analysis_period}</p>
    </div>
    
    {content}
    
    <script>
        // Tab functionality
        function openTab(evt, tabName) {{
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {{
                tabcontent[i].classList.remove("active");
            }}
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {{
                tablinks[i].classList.remove("active");
            }}
            document.getElementById(tabName).classList.add("active");
            evt.currentTarget.classList.add("active");
        }}
        
        // Initialize first tab
        document.addEventListener('DOMContentLoaded', function() {{
            const firstTab = document.querySelector('.tab-button');
            if (firstTab) firstTab.click();
        }});
    </script>
</body>
</html>
            ''',
            
            'executive_summary': '''
<div class="section">
    <h2>📊 Executive Summary</h2>
    <div style="display: flex; flex-wrap: wrap;">
        <div class="metric">
            <div class="metric-value">{total_calls}</div>
            <div class="metric-label">Total API Calls</div>
        </div>
        <div class="metric">
            <div class="metric-value">{unique_apis}</div>
            <div class="metric-label">Unique APIs</div>
        </div>
        <div class="metric">
            <div class="metric-value">{patterns_detected}</div>
            <div class="metric-label">Patterns Detected</div>
        </div>
        <div class="metric">
            <div class="metric-value">{anomalies_found}</div>
            <div class="metric-label">Anomalies Found</div>
        </div>
        <div class="metric">
            <div class="metric-value">{protection_mechanisms}</div>
            <div class="metric-label">Protection Mechanisms</div>
        </div>
        <div class="metric">
            <div class="metric-value">{calls_per_second:.1f}</div>
            <div class="metric-label">Calls per Second</div>
        </div>
    </div>
    
    <h3>🎯 Key Findings</h3>
    <ul>
        {key_findings}
    </ul>
</div>
            '''
        }
    
    def generate_comprehensive_report(self,
                                    api_calls: List[APICall],
                                    patterns: List[DetectedPattern],
                                    call_chains: List[CallChain],
                                    anomalies: List[StackAnomaly],
                                    correlation_events: List[CorrelationEvent],
                                    output_path: Path,
                                    format: ReportFormat = ReportFormat.HTML) -> bool:
        """
        Generate comprehensive API trace analysis report.
        
        Args:
            api_calls: List of API calls to analyze
            patterns: List of detected patterns
            call_chains: List of identified call chains
            anomalies: List of stack anomalies
            correlation_events: List of correlation events
            output_path: Path for output file
            format: Report format
            
        Returns:
            True if report generated successfully, False otherwise
        """
        try:
            logger.info("Generating comprehensive API trace report...")
            
            # Analyze data
            analysis_results = self._analyze_trace_data(
                api_calls, patterns, call_chains, anomalies, correlation_events
            )
            
            # Generate report based on format
            if format == ReportFormat.HTML:
                return self._generate_html_report(analysis_results, output_path)
            elif format == ReportFormat.JSON:
                return self._generate_json_report(analysis_results, output_path)
            elif format == ReportFormat.CSV:
                return self._generate_csv_report(analysis_results, output_path)
            else:
                logger.error("Unsupported report format: %s", format)
                return False
                
        except Exception as e:
            logger.error("Failed to generate report: %s", e)
            return False
    
    def _analyze_trace_data(self,
                           api_calls: List[APICall],
                           patterns: List[DetectedPattern],
                           call_chains: List[CallChain],
                           anomalies: List[StackAnomaly],
                           correlation_events: List[CorrelationEvent]) -> Dict[str, Any]:
        """Analyze trace data and generate comprehensive insights."""
        
        # Basic statistics
        total_calls = len(api_calls)
        if not api_calls:
            return {'error': 'No API calls to analyze'}
        
        start_time = min(call.timestamp for call in api_calls)
        end_time = max(call.timestamp for call in api_calls)
        duration = end_time - start_time
        
        # API call analysis
        api_stats = self._analyze_api_calls(api_calls)
        
        # Pattern analysis
        pattern_stats = self._analyze_patterns(patterns)
        
        # Call chain analysis
        chain_stats = self._analyze_call_chains(call_chains)
        
        # Anomaly analysis
        anomaly_stats = self._analyze_anomalies(anomalies)
        
        # Correlation event analysis
        correlation_stats = self._analyze_correlation_events(correlation_events)
        
        # Timeline analysis
        timeline_data = self._generate_timeline_data(api_calls)
        
        # Protection mechanism identification
        protection_analysis = self._identify_protection_mechanisms(api_calls, patterns)
        
        # Bypass recommendations
        bypass_recommendations = self._generate_bypass_recommendations(
            protection_analysis, patterns, anomalies
        )
        
        return {
            'metadata': {
                'generation_time': datetime.now().isoformat(),
                'analysis_period': f"{datetime.fromtimestamp(start_time)} - {datetime.fromtimestamp(end_time)}",
                'duration_seconds': duration,
                'total_calls': total_calls
            },
            'api_stats': api_stats,
            'pattern_stats': pattern_stats,
            'chain_stats': chain_stats,
            'anomaly_stats': anomaly_stats,
            'correlation_stats': correlation_stats,
            'timeline_data': timeline_data,
            'protection_analysis': protection_analysis,
            'bypass_recommendations': bypass_recommendations,
            'raw_data': {
                'api_calls': api_calls,
                'patterns': patterns,
                'call_chains': call_chains,
                'anomalies': anomalies,
                'correlation_events': correlation_events
            }
        }
    
    def _analyze_api_calls(self, api_calls: List[APICall]) -> Dict[str, Any]:
        """Analyze API calls for statistics and patterns."""
        if not api_calls:
            return {}
        
        # Basic counts
        function_counts = Counter(call.function for call in api_calls)
        module_counts = Counter(call.module for call in api_calls)
        category_counts = Counter(call.category.name for call in api_calls)
        
        # Timing analysis
        execution_times = [call.execution_time_ms for call in api_calls if call.execution_time_ms > 0]
        
        # Thread analysis
        thread_counts = Counter(call.thread_id for call in api_calls)
        
        # Frequency analysis
        start_time = min(call.timestamp for call in api_calls)
        end_time = max(call.timestamp for call in api_calls)
        duration = end_time - start_time
        calls_per_second = len(api_calls) / duration if duration > 0 else 0
        
        return {
            'total_calls': len(api_calls),
            'unique_functions': len(function_counts),
            'unique_modules': len(module_counts),
            'calls_per_second': calls_per_second,
            'duration_seconds': duration,
            'top_functions': function_counts.most_common(10),
            'top_modules': module_counts.most_common(10),
            'category_distribution': dict(category_counts),
            'thread_distribution': dict(thread_counts),
            'execution_time_stats': {
                'avg_ms': statistics.mean(execution_times) if execution_times else 0,
                'median_ms': statistics.median(execution_times) if execution_times else 0,
                'max_ms': max(execution_times) if execution_times else 0,
                'min_ms': min(execution_times) if execution_times else 0
            }
        }
    
    def _analyze_patterns(self, patterns: List[DetectedPattern]) -> Dict[str, Any]:
        """Analyze detected patterns."""
        if not patterns:
            return {'total_patterns': 0}
        
        type_counts = Counter(pattern.pattern_type.name for pattern in patterns)
        severity_counts = Counter(pattern.severity.name for pattern in patterns)
        
        # Confidence analysis
        confidences = [pattern.confidence for pattern in patterns]
        
        # Temporal analysis
        pattern_times = [pattern.timestamp for pattern in patterns]
        
        return {
            'total_patterns': len(patterns),
            'type_distribution': dict(type_counts),
            'severity_distribution': dict(severity_counts),
            'confidence_stats': {
                'avg': statistics.mean(confidences),
                'median': statistics.median(confidences),
                'min': min(confidences),
                'max': max(confidences)
            },
            'top_pattern_types': type_counts.most_common(5),
            'critical_patterns': len([p for p in patterns if p.severity == PatternSeverity.CRITICAL]),
            'high_confidence_patterns': len([p for p in patterns if p.confidence > 0.8])
        }
    
    def _analyze_call_chains(self, call_chains: List[CallChain]) -> Dict[str, Any]:
        """Analyze call chains."""
        if not call_chains:
            return {'total_chains': 0}
        
        pattern_counts = Counter(chain.pattern_type.name for chain in call_chains)
        
        # Duration analysis
        durations = [chain.duration_ms for chain in call_chains]
        
        # Call count analysis
        call_counts = [chain.call_count for chain in call_chains]
        
        return {
            'total_chains': len(call_chains),
            'pattern_distribution': dict(pattern_counts),
            'duration_stats': {
                'avg_ms': statistics.mean(durations),
                'median_ms': statistics.median(durations),
                'max_ms': max(durations),
                'min_ms': min(durations)
            },
            'call_count_stats': {
                'avg': statistics.mean(call_counts),
                'median': statistics.median(call_counts),
                'max': max(call_counts),
                'min': min(call_counts)
            }
        }
    
    def _analyze_anomalies(self, anomalies: List[StackAnomaly]) -> Dict[str, Any]:
        """Analyze stack anomalies."""
        if not anomalies:
            return {'total_anomalies': 0}
        
        type_counts = Counter(anomaly.anomaly_type.name for anomaly in anomalies)
        severity_counts = Counter(anomaly.severity for anomaly in anomalies)
        
        return {
            'total_anomalies': len(anomalies),
            'type_distribution': dict(type_counts),
            'severity_distribution': dict(severity_counts),
            'critical_anomalies': len([a for a in anomalies if a.severity == 'critical']),
            'recent_anomalies': len([a for a in anomalies if time.time() - a.timestamp < 300])
        }
    
    def _analyze_correlation_events(self, correlation_events: List[CorrelationEvent]) -> Dict[str, Any]:
        """Analyze correlation events."""
        if not correlation_events:
            return {'total_events': 0}
        
        event_type_counts = Counter(event.event_type.name for event in correlation_events)
        severity_counts = Counter(event.severity.name for event in correlation_events)
        
        return {
            'total_events': len(correlation_events),
            'event_type_distribution': dict(event_type_counts),
            'severity_distribution': dict(severity_counts),
            'critical_events': len([e for e in correlation_events if e.severity.name == 'CRITICAL'])
        }
    
    def _generate_timeline_data(self, api_calls: List[APICall]) -> Dict[str, Any]:
        """Generate timeline visualization data."""
        if not api_calls:
            return {}
        
        # Create time buckets (100 buckets across the timeline)
        start_time = min(call.timestamp for call in api_calls)
        end_time = max(call.timestamp for call in api_calls)
        duration = end_time - start_time
        
        if duration <= 0:
            return {}
        
        bucket_count = min(100, len(api_calls))
        bucket_size = duration / bucket_count
        
        timeline_buckets = defaultdict(lambda: defaultdict(int))
        
        for call in api_calls:
            bucket_idx = int((call.timestamp - start_time) / bucket_size)
            timeline_buckets[bucket_idx][call.category.name] += 1
        
        # Generate chart data
        timestamps = []
        categories = set()
        for call in api_calls:
            categories.add(call.category.name)
        
        chart_data = {category: [] for category in categories}
        
        for i in range(bucket_count):
            bucket_time = start_time + (i * bucket_size)
            timestamps.append(datetime.fromtimestamp(bucket_time).isoformat())
            
            for category in categories:
                chart_data[category].append(timeline_buckets[i][category])
        
        return {
            'timestamps': timestamps,
            'categories': list(categories),
            'data': chart_data,
            'bucket_size_seconds': bucket_size
        }
    
    def _identify_protection_mechanisms(self, api_calls: List[APICall], patterns: List[DetectedPattern]) -> Dict[str, Any]:
        """Identify protection mechanisms from API calls and patterns."""
        protection_indicators = {
            'anti_debug': [],
            'anti_vm': [],
            'license_validation': [],
            'integrity_checks': [],
            'time_bombs': [],
            'hardware_fingerprinting': [],
            'network_validation': []
        }
        
        # Analyze API calls for protection indicators
        for call in api_calls:
            function_lower = call.function.lower()
            
            # Anti-debugging
            if any(indicator in function_lower for indicator in ['debugger', 'debug']):
                protection_indicators['anti_debug'].append({
                    'api': f"{call.module}!{call.function}",
                    'timestamp': call.timestamp,
                    'parameters': call.parameters[:3] if call.parameters else []
                })
            
            # Anti-VM
            if any(indicator in function_lower for indicator in ['virtual', 'vmware', 'vbox']):
                protection_indicators['anti_vm'].append({
                    'api': f"{call.module}!{call.function}",
                    'timestamp': call.timestamp
                })
            
            # License validation
            if any(indicator in str(call.parameters).lower() for indicator in ['license', 'trial', 'activate']):
                protection_indicators['license_validation'].append({
                    'api': f"{call.module}!{call.function}",
                    'timestamp': call.timestamp,
                    'parameters': call.parameters[:3] if call.parameters else []
                })
            
            # Hardware fingerprinting
            if any(indicator in function_lower for indicator in ['volume', 'disk', 'adapter', 'hardware']):
                protection_indicators['hardware_fingerprinting'].append({
                    'api': f"{call.module}!{call.function}",
                    'timestamp': call.timestamp
                })
        
        # Analyze patterns for additional protection mechanisms
        for pattern in patterns:
            if pattern.pattern_type == PatternType.LICENSE_VALIDATION:
                protection_indicators['license_validation'].extend(pattern.metadata.get('apis', []))
            elif pattern.pattern_type == PatternType.ANTI_DEBUG_SEQUENCE:
                protection_indicators['anti_debug'].extend(pattern.metadata.get('apis', []))
            elif pattern.pattern_type == PatternType.TIME_BOMB_DETECTION:
                protection_indicators['time_bombs'].extend(pattern.metadata.get('apis', []))
        
        # Calculate protection strength scores
        protection_scores = {}
        for mechanism, indicators in protection_indicators.items():
            if indicators:
                # Score based on number of indicators and their frequency
                unique_apis = len(set(ind.get('api', '') for ind in indicators))
                total_calls = len(indicators)
                protection_scores[mechanism] = min(100, (unique_apis * 10) + (total_calls * 2))
            else:
                protection_scores[mechanism] = 0
        
        return {
            'indicators': protection_indicators,
            'scores': protection_scores,
            'total_mechanisms': len([m for m, score in protection_scores.items() if score > 0]),
            'strongest_protection': max(protection_scores.items(), key=lambda x: x[1]) if protection_scores else None
        }
    
    def _generate_bypass_recommendations(self,
                                       protection_analysis: Dict[str, Any],
                                       patterns: List[DetectedPattern],
                                       anomalies: List[StackAnomaly]) -> List[Dict[str, Any]]:
        """Generate bypass strategy recommendations."""
        recommendations = []
        
        protection_scores = protection_analysis.get('scores', {})
        
        # Anti-debugging bypass recommendations
        if protection_scores.get('anti_debug', 0) > 20:
            recommendations.append({
                'target': 'Anti-Debugging',
                'priority': 'High',
                'strategy': 'API Hooking',
                'description': 'Hook IsDebuggerPresent, CheckRemoteDebuggerPresent, and NtQueryInformationProcess to return false',
                'frida_script': '''
// Anti-debugging bypass
Interceptor.attach(Module.findExportByName("kernel32.dll", "IsDebuggerPresent"), {
    onLeave: function(retval) {
        retval.replace(0);
    }
});
                ''',
                'confidence': 0.9
            })
        
        # License validation bypass recommendations
        if protection_scores.get('license_validation', 0) > 30:
            recommendations.append({
                'target': 'License Validation',
                'priority': 'Critical',
                'strategy': 'Registry Manipulation + Crypto Bypass',
                'description': 'Intercept registry queries and cryptographic operations to simulate valid license',
                'frida_script': '''
// License validation bypass
Interceptor.attach(Module.findExportByName("advapi32.dll", "RegQueryValueExW"), {
    onLeave: function(retval) {
        // Check if querying license-related keys and modify return
        if (this.keyName && this.keyName.toLowerCase().includes("license")) {
            retval.replace(0); // ERROR_SUCCESS
        }
    }
});
                ''',
                'confidence': 0.8
            })
        
        # Time bomb bypass recommendations
        if any(p.pattern_type == PatternType.TIME_BOMB_DETECTION for p in patterns):
            recommendations.append({
                'target': 'Time Bomb',
                'priority': 'High',
                'strategy': 'Time Manipulation',
                'description': 'Hook time-related APIs to return fixed timestamps',
                'frida_script': '''
// Time bomb bypass
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetSystemTime"), {
    onLeave: function(retval) {
        // Return a fixed date in the past
        Memory.writeU64(this.context.r8, 0x01d0abcd12345678);
    }
});
                ''',
                'confidence': 0.7
            })
        
        # Hardware fingerprinting bypass
        if protection_scores.get('hardware_fingerprinting', 0) > 25:
            recommendations.append({
                'target': 'Hardware Fingerprinting',
                'priority': 'Medium',
                'strategy': 'Hardware Spoofing',
                'description': 'Spoof hardware identifiers like disk serial numbers and MAC addresses',
                'frida_script': '''
// Hardware fingerprinting bypass
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetVolumeInformationW"), {
    onLeave: function(retval) {
        // Modify volume serial number
        if (this.context.r9) {
            Memory.writeU32(this.context.r9, 0x12345678);
        }
    }
});
                ''',
                'confidence': 0.6
            })
        
        # Add recommendations based on anomalies
        critical_anomalies = [a for a in anomalies if a.severity == 'critical']
        if critical_anomalies:
            recommendations.append({
                'target': 'Code Injection Detection',
                'priority': 'Critical',
                'strategy': 'Memory Protection Bypass',
                'description': 'Detected code injection patterns - consider bypassing memory protection checks',
                'frida_script': '''
// Memory protection bypass
Interceptor.attach(Module.findExportByName("kernel32.dll", "VirtualProtect"), {
    onLeave: function(retval) {
        retval.replace(1); // Always return success
    }
});
                ''',
                'confidence': 0.8
            })
        
        return recommendations
    
    def _generate_html_report(self, analysis_results: Dict[str, Any], output_path: Path) -> bool:
        """Generate HTML report."""
        try:
            # Extract data for template
            metadata = analysis_results['metadata']
            api_stats = analysis_results['api_stats']
            pattern_stats = analysis_results['pattern_stats']
            protection_analysis = analysis_results['protection_analysis']
            bypass_recommendations = analysis_results['bypass_recommendations']
            
            # Generate executive summary
            executive_summary = self.report_templates['executive_summary'].format(
                total_calls=api_stats.get('total_calls', 0),
                unique_apis=api_stats.get('unique_functions', 0),
                patterns_detected=pattern_stats.get('total_patterns', 0),
                anomalies_found=analysis_results['anomaly_stats'].get('total_anomalies', 0),
                protection_mechanisms=protection_analysis.get('total_mechanisms', 0),
                calls_per_second=api_stats.get('calls_per_second', 0),
                key_findings=self._generate_key_findings_html(analysis_results)
            )
            
            # Generate detailed sections
            sections = []
            sections.append(executive_summary)
            sections.append(self._generate_api_analysis_section(api_stats))
            sections.append(self._generate_pattern_analysis_section(pattern_stats, analysis_results['raw_data']['patterns']))
            sections.append(self._generate_protection_analysis_section(protection_analysis))
            sections.append(self._generate_bypass_recommendations_section(bypass_recommendations))
            sections.append(self._generate_timeline_section(analysis_results['timeline_data']))
            
            # Combine all sections
            content = '\n'.join(sections)
            
            # Generate final HTML
            html_content = self.report_templates['main'].format(
                timestamp=metadata['generation_time'],
                analysis_period=metadata['analysis_period'],
                content=content
            )
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info("HTML report generated: %s", output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to generate HTML report: %s", e)
            return False
    
    def _generate_key_findings_html(self, analysis_results: Dict[str, Any]) -> str:
        """Generate key findings HTML."""
        findings = []
        
        api_stats = analysis_results['api_stats']
        pattern_stats = analysis_results['pattern_stats']
        protection_analysis = analysis_results['protection_analysis']
        
        # High API call rate
        if api_stats.get('calls_per_second', 0) > 100:
            findings.append("<li>🔥 <strong>High API call rate detected</strong> - May indicate intensive protection or monitoring</li>")
        
        # Critical patterns
        if pattern_stats.get('critical_patterns', 0) > 0:
            findings.append(f"<li>⚠️ <strong>{pattern_stats['critical_patterns']} critical patterns detected</strong> - Immediate attention required</li>")
        
        # Protection mechanisms
        if protection_analysis.get('total_mechanisms', 0) > 3:
            findings.append(f"<li>🛡️ <strong>Multiple protection mechanisms active</strong> - {protection_analysis['total_mechanisms']} different types detected</li>")
        
        # License validation
        if protection_analysis.get('scores', {}).get('license_validation', 0) > 50:
            findings.append("<li>🔐 <strong>Strong license validation detected</strong> - Consider targeted bypass strategies</li>")
        
        if not findings:
            findings.append("<li>ℹ️ No critical issues detected in this analysis period</li>")
        
        return '\n        '.join(findings)
    
    def _generate_api_analysis_section(self, api_stats: Dict[str, Any]) -> str:
        """Generate API analysis section."""
        if not api_stats:
            return ""
        
        top_functions_html = ""
        for func, count in api_stats.get('top_functions', []):
            top_functions_html += f"<tr><td class='api-call'>{func}</td><td>{count}</td></tr>"
        
        category_distribution_html = ""
        for category, count in api_stats.get('category_distribution', {}).items():
            category_distribution_html += f"<tr><td>{category}</td><td>{count}</td></tr>"
        
        return f'''
<div class="section">
    <h2>📊 API Call Analysis</h2>
    
    <div class="tabs">
        <button class="tab-button" onclick="openTab(event, 'api-overview')">Overview</button>
        <button class="tab-button" onclick="openTab(event, 'api-functions')">Top Functions</button>
        <button class="tab-button" onclick="openTab(event, 'api-categories')">Categories</button>
    </div>
    
    <div id="api-overview" class="tab-content">
        <h3>Call Statistics</h3>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total API Calls</td><td>{api_stats.get('total_calls', 0):,}</td></tr>
            <tr><td>Unique Functions</td><td>{api_stats.get('unique_functions', 0)}</td></tr>
            <tr><td>Unique Modules</td><td>{api_stats.get('unique_modules', 0)}</td></tr>
            <tr><td>Calls per Second</td><td>{api_stats.get('calls_per_second', 0):.2f}</td></tr>
            <tr><td>Average Execution Time</td><td>{api_stats.get('execution_time_stats', {}).get('avg_ms', 0):.2f} ms</td></tr>
        </table>
    </div>
    
    <div id="api-functions" class="tab-content">
        <h3>Most Called Functions</h3>
        <table>
            <tr><th>Function</th><th>Call Count</th></tr>
            {top_functions_html}
        </table>
    </div>
    
    <div id="api-categories" class="tab-content">
        <h3>API Category Distribution</h3>
        <table>
            <tr><th>Category</th><th>Count</th></tr>
            {category_distribution_html}
        </table>
    </div>
</div>
        '''
    
    def _generate_pattern_analysis_section(self, pattern_stats: Dict[str, Any], patterns: List[DetectedPattern]) -> str:
        """Generate pattern analysis section."""
        if not patterns:
            return "<div class='section'><h2>🔍 Pattern Analysis</h2><p>No patterns detected.</p></div>"
        
        patterns_html = ""
        for pattern in patterns[:20]:  # Show top 20 patterns
            severity_class = f"pattern-{pattern.severity.name.lower()}"
            patterns_html += f'''
            <div class="pattern-item {severity_class}">
                <h4>{pattern.pattern_type.name.replace('_', ' ').title()}</h4>
                <p>{pattern.description}</p>
                <div class="timestamp">Detected: {datetime.fromtimestamp(pattern.timestamp).strftime('%Y-%m-%d %H:%M:%S')} | 
                Confidence: {pattern.confidence:.2f} | Severity: <span class="severity-{pattern.severity.name.lower()}">{pattern.severity.name}</span></div>
            </div>
            '''
        
        return f'''
<div class="section">
    <h2>🔍 Pattern Analysis</h2>
    <p>Detected {pattern_stats.get('total_patterns', 0)} patterns with average confidence of {pattern_stats.get('confidence_stats', {}).get('avg', 0):.2f}</p>
    
    <h3>Detected Patterns</h3>
    {patterns_html}
</div>
        '''
    
    def _generate_protection_analysis_section(self, protection_analysis: Dict[str, Any]) -> str:
        """Generate protection analysis section."""
        scores = protection_analysis.get('scores', {})
        
        protection_html = ""
        for mechanism, score in scores.items():
            if score > 0:
                bar_width = min(100, score)
                protection_html += f'''
                <div style="margin: 10px 0;">
                    <div style="display: flex; justify-content: space-between;">
                        <span>{mechanism.replace('_', ' ').title()}</span>
                        <span>{score}/100</span>
                    </div>
                    <div style="background: #e9ecef; height: 20px; border-radius: 10px;">
                        <div style="background: #007bff; height: 100%; width: {bar_width}%; border-radius: 10px;"></div>
                    </div>
                </div>
                '''
        
        return f'''
<div class="section">
    <h2>🛡️ Protection Mechanism Analysis</h2>
    <p>Identified {protection_analysis.get('total_mechanisms', 0)} active protection mechanisms</p>
    
    <h3>Protection Strength Assessment</h3>
    {protection_html}
</div>
        '''
    
    def _generate_bypass_recommendations_section(self, recommendations: List[Dict[str, Any]]) -> str:
        """Generate bypass recommendations section."""
        if not recommendations:
            return "<div class='section'><h2>💡 Bypass Recommendations</h2><p>No specific bypass strategies recommended.</p></div>"
        
        recommendations_html = ""
        for rec in recommendations:
            recommendations_html += f'''
            <div class="recommendation">
                <h4>🎯 {rec['target']} - {rec['strategy']}</h4>
                <p><strong>Priority:</strong> {rec['priority']} | <strong>Confidence:</strong> {rec['confidence']:.1%}</p>
                <p>{rec['description']}</p>
                <details>
                    <summary>Frida Script Example</summary>
                    <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto;"><code>{rec['frida_script']}</code></pre>
                </details>
            </div>
            '''
        
        return f'''
<div class="section">
    <h2>💡 Bypass Recommendations</h2>
    <p>Generated {len(recommendations)} targeted bypass strategies based on detected protection mechanisms</p>
    {recommendations_html}
</div>
        '''
    
    def _generate_timeline_section(self, timeline_data: Dict[str, Any]) -> str:
        """Generate timeline visualization section."""
        if not timeline_data:
            return ""
        
        # Generate Plotly chart data
        chart_json = json.dumps({
            'data': [
                {
                    'x': timeline_data['timestamps'],
                    'y': timeline_data['data'][category],
                    'name': category,
                    'type': 'scatter',
                    'mode': 'lines+markers'
                }
                for category in timeline_data['categories']
            ],
            'layout': {
                'title': 'API Call Timeline',
                'xaxis': {'title': 'Time'},
                'yaxis': {'title': 'Number of Calls'},
                'hovermode': 'x unified'
            }
        })
        
        return f'''
<div class="section">
    <h2>📈 API Call Timeline</h2>
    <div id="timeline-chart" class="chart-container"></div>
    <script>
        Plotly.newPlot('timeline-chart', {chart_json}.data, {chart_json}.layout);
    </script>
</div>
        '''
    
    def _generate_json_report(self, analysis_results: Dict[str, Any], output_path: Path) -> bool:
        """Generate JSON report."""
        try:
            # Remove raw data to avoid serialization issues
            report_data = analysis_results.copy()
            if 'raw_data' in report_data:
                # Convert raw data to serializable format
                raw_data = report_data['raw_data']
                report_data['raw_data'] = {
                    'api_calls': [call.to_dict() for call in raw_data.get('api_calls', [])],
                    'patterns': [pattern.to_dict() for pattern in raw_data.get('patterns', [])],
                    'call_chains': [chain.to_dict() for chain in raw_data.get('call_chains', [])],
                    'anomalies': [anomaly.to_dict() for anomaly in raw_data.get('anomalies', [])],
                    'correlation_events': [event.to_dict() for event in raw_data.get('correlation_events', [])]
                }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            logger.info("JSON report generated: %s", output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to generate JSON report: %s", e)
            return False
    
    def _generate_csv_report(self, analysis_results: Dict[str, Any], output_path: Path) -> bool:
        """Generate CSV report."""
        try:
            import csv
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write API calls
                writer.writerow(['API Calls'])
                writer.writerow(['Timestamp', 'Module', 'Function', 'Category', 'Thread ID', 'Execution Time (ms)'])
                
                for call in analysis_results['raw_data'].get('api_calls', []):
                    writer.writerow([
                        datetime.fromtimestamp(call.timestamp).isoformat(),
                        call.module,
                        call.function,
                        call.category.name,
                        call.thread_id,
                        call.execution_time_ms
                    ])
                
                # Write patterns
                writer.writerow([])
                writer.writerow(['Detected Patterns'])
                writer.writerow(['Timestamp', 'Type', 'Severity', 'Confidence', 'Description'])
                
                for pattern in analysis_results['raw_data'].get('patterns', []):
                    writer.writerow([
                        datetime.fromtimestamp(pattern.timestamp).isoformat(),
                        pattern.pattern_type.name,
                        pattern.severity.name,
                        pattern.confidence,
                        pattern.description
                    ])
            
            logger.info("CSV report generated: %s", output_path)
            return True
            
        except Exception as e:
            logger.error("Failed to generate CSV report: %s", e)
            return False