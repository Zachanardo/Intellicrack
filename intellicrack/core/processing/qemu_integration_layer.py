"""
QEMU Integration Layer for Enhanced Snapshot Diffing.

This module provides seamless integration between the existing QEMUSystemEmulator
and the new comprehensive snapshot diffing system, maintaining backward compatibility
while adding advanced behavior analysis capabilities.

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

import asyncio
import time
from typing import Any, Dict, List, Optional

from intellicrack.logger import logger

from .qemu_snapshot_differ import QEMUSnapshotDiffer, create_snapshot_differ


class QEMUEmulatorEnhanced:
    """
    Enhanced QEMU emulator with integrated snapshot diffing capabilities.
    
    This class wraps the existing QEMUSystemEmulator to provide advanced
    snapshot management and behavior analysis while maintaining full
    backward compatibility with existing code.
    """
    
    def __init__(self, qemu_emulator):
        """
        Initialize enhanced emulator wrapper.
        
        Args:
            qemu_emulator: Existing QEMUSystemEmulator instance
        """
        self.qemu_emulator = qemu_emulator
        self.snapshot_differ: Optional[QEMUSnapshotDiffer] = None
        self.analysis_mode = False
        self.auto_snapshot_interval = 30.0  # seconds
        self.auto_snapshot_task: Optional[asyncio.Task] = None
        
        # Analysis state tracking
        self.baseline_established = False
        self.analysis_session_id = None
        self.behavior_timeline = []
        
    async def initialize_advanced_analysis(self, storage_path: str = None) -> bool:
        """
        Initialize advanced snapshot diffing capabilities.
        
        Args:
            storage_path: Path to store snapshots and analysis data
            
        Returns:
            True if initialization successful
        """
        try:
            self.snapshot_differ = await create_snapshot_differ(
                self.qemu_emulator, storage_path
            )
            
            logger.info("Advanced QEMU analysis capabilities initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize advanced analysis: {e}")
            return False
    
    async def start_behavior_analysis_session(self, session_name: str = None) -> str:
        """
        Start a new behavior analysis session with automatic baseline.
        
        Args:
            session_name: Optional name for the analysis session
            
        Returns:
            Session ID for tracking analysis
        """
        if not self.snapshot_differ:
            await self.initialize_advanced_analysis()
        
        session_id = session_name or f"analysis_{int(time.time())}"
        self.analysis_session_id = session_id
        self.analysis_mode = True
        self.behavior_timeline = []
        
        # Create baseline snapshot
        baseline_name = f"{session_id}_baseline"
        if await self.snapshot_differ.create_snapshot(baseline_name, {
            "session_id": session_id,
            "snapshot_type": "baseline",
            "created_by": "behavior_analysis_session"
        }):
            await self.snapshot_differ.set_baseline(baseline_name)
            self.baseline_established = True
            logger.info(f"Behavior analysis session started: {session_id}")
        else:
            logger.error("Failed to create baseline snapshot")
            self.analysis_mode = False
            return None
        
        return session_id
    
    async def take_analysis_checkpoint(self, checkpoint_name: str = None, 
                                     annotations: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Take an analysis checkpoint and compare with baseline.
        
        Args:
            checkpoint_name: Name for the checkpoint
            annotations: Additional metadata for the checkpoint
            
        Returns:
            Analysis results or None if failed
        """
        if not self.analysis_mode or not self.snapshot_differ:
            logger.error("Analysis mode not active")
            return None
        
        checkpoint_name = checkpoint_name or f"{self.analysis_session_id}_checkpoint_{len(self.behavior_timeline)}"
        
        # Create checkpoint snapshot
        checkpoint_annotations = {
            "session_id": self.analysis_session_id,
            "snapshot_type": "checkpoint",
            "checkpoint_index": len(self.behavior_timeline)
        }
        if annotations:
            checkpoint_annotations.update(annotations)
        
        if await self.snapshot_differ.create_snapshot(checkpoint_name, checkpoint_annotations):
            # Analyze changes since baseline
            analysis_result = await self.snapshot_differ.analyze_since_baseline(checkpoint_name)
            
            if analysis_result:
                # Add to behavior timeline
                timeline_entry = {
                    "checkpoint_name": checkpoint_name,
                    "timestamp": time.time(),
                    "annotations": checkpoint_annotations,
                    "analysis": analysis_result
                }
                self.behavior_timeline.append(timeline_entry)
                
                logger.info(f"Analysis checkpoint created: {checkpoint_name}")
                return analysis_result
        
        logger.error(f"Failed to create analysis checkpoint: {checkpoint_name}")
        return None
    
    async def execute_with_analysis(self, binary_path: str, 
                                   pre_execution_checkpoint: bool = True,
                                   post_execution_checkpoint: bool = True,
                                   monitor_during_execution: bool = False) -> Dict[str, Any]:
        """
        Execute binary with comprehensive behavior analysis.
        
        Args:
            binary_path: Path to binary to execute
            pre_execution_checkpoint: Take checkpoint before execution
            post_execution_checkpoint: Take checkpoint after execution  
            monitor_during_execution: Monitor changes during execution
            
        Returns:
            Comprehensive analysis results
        """
        if not self.analysis_mode:
            session_id = await self.start_behavior_analysis_session()
            if not session_id:
                return {"error": "Failed to start analysis session"}
        
        execution_results = {
            "binary_path": binary_path,
            "session_id": self.analysis_session_id,
            "execution_start": time.time(),
            "pre_execution_analysis": None,
            "execution_monitoring": None,
            "post_execution_analysis": None,
            "summary": {}
        }
        
        try:
            # Pre-execution checkpoint
            if pre_execution_checkpoint:
                pre_analysis = await self.take_analysis_checkpoint(
                    f"{self.analysis_session_id}_pre_execution",
                    {"phase": "pre_execution", "binary_path": binary_path}
                )
                execution_results["pre_execution_analysis"] = pre_analysis
            
            # Start monitoring if requested
            monitoring_task = None
            if monitor_during_execution:
                monitoring_task = asyncio.create_task(
                    self.snapshot_differ.monitor_realtime_changes(
                        interval=2.0, duration=60.0
                    )
                )
            
            # Execute binary using existing implementation
            execution_result = self.qemu_emulator._execute_binary_analysis(binary_path)
            
            # Wait for monitoring to complete if it was running
            if monitoring_task:
                try:
                    monitoring_results = await asyncio.wait_for(monitoring_task, timeout=65.0)
                    execution_results["execution_monitoring"] = monitoring_results
                except asyncio.TimeoutError:
                    monitoring_task.cancel()
                    logger.warning("Execution monitoring timed out")
            
            # Post-execution checkpoint
            if post_execution_checkpoint:
                post_analysis = await self.take_analysis_checkpoint(
                    f"{self.analysis_session_id}_post_execution",
                    {"phase": "post_execution", "binary_path": binary_path, "execution_result": execution_result}
                )
                execution_results["post_execution_analysis"] = post_analysis
            
            # Generate execution summary
            execution_results["summary"] = self._generate_execution_summary(execution_results)
            execution_results["execution_end"] = time.time()
            execution_results["total_duration"] = execution_results["execution_end"] - execution_results["execution_start"]
            
            logger.info(f"Binary analysis with behavior monitoring completed for {binary_path}")
            
        except Exception as e:
            logger.error(f"Error during execution with analysis: {e}")
            execution_results["error"] = str(e)
        
        return execution_results
    
    async def analyze_license_check_sequence(self, trigger_action: callable,
                                           action_description: str = "license_check") -> Dict[str, Any]:
        """
        Analyze a specific license check sequence with detailed monitoring.
        
        Args:
            trigger_action: Callable that triggers the license check
            action_description: Description of the action being performed
            
        Returns:
            Detailed analysis of the license check behavior
        """
        if not self.analysis_mode:
            session_id = await self.start_behavior_analysis_session()
            if not session_id:
                return {"error": "Failed to start analysis session"}
        
        license_analysis = {
            "action_description": action_description,
            "session_id": self.analysis_session_id,
            "analysis_start": time.time(),
            "pre_action_state": None,
            "action_monitoring": None,
            "post_action_state": None,
            "license_indicators": {},
            "recommendations": []
        }
        
        try:
            # Capture pre-action state
            pre_action_analysis = await self.take_analysis_checkpoint(
                f"{self.analysis_session_id}_pre_{action_description}",
                {"phase": "pre_action", "action": action_description}
            )
            license_analysis["pre_action_state"] = pre_action_analysis
            
            # Start detailed monitoring with short intervals for license checks
            monitoring_task = asyncio.create_task(
                self.snapshot_differ.monitor_realtime_changes(
                    interval=0.5, duration=10.0  # High frequency, short duration
                )
            )
            
            # Execute the license check trigger action
            action_start = time.time()
            action_result = None
            if asyncio.iscoroutinefunction(trigger_action):
                action_result = await trigger_action()
            else:
                action_result = trigger_action()
            action_duration = time.time() - action_start
            
            # Wait for monitoring results
            try:
                monitoring_results = await asyncio.wait_for(monitoring_task, timeout=12.0)
                license_analysis["action_monitoring"] = monitoring_results
            except asyncio.TimeoutError:
                monitoring_task.cancel()
                logger.warning("License check monitoring timed out")
            
            # Capture post-action state
            post_action_analysis = await self.take_analysis_checkpoint(
                f"{self.analysis_session_id}_post_{action_description}",
                {"phase": "post_action", "action": action_description, "action_duration": action_duration}
            )
            license_analysis["post_action_state"] = post_action_analysis
            
            # Analyze license-specific indicators
            license_analysis["license_indicators"] = self._analyze_license_specific_behavior(
                pre_action_analysis, post_action_analysis, monitoring_results if 'monitoring_results' in locals() else None
            )
            
            # Generate recommendations
            license_analysis["recommendations"] = self._generate_license_recommendations(license_analysis)
            
            license_analysis["analysis_end"] = time.time()
            license_analysis["total_duration"] = license_analysis["analysis_end"] - license_analysis["analysis_start"]
            
            logger.info(f"License check analysis completed for: {action_description}")
            
        except Exception as e:
            logger.error(f"Error during license check analysis: {e}")
            license_analysis["error"] = str(e)
        
        return license_analysis
    
    async def start_automatic_monitoring(self, interval: float = None) -> bool:
        """
        Start automatic periodic snapshot monitoring.
        
        Args:
            interval: Snapshot interval in seconds (default: 30.0)
            
        Returns:
            True if monitoring started successfully
        """
        if not self.snapshot_differ:
            await self.initialize_advanced_analysis()
        
        if self.auto_snapshot_task and not self.auto_snapshot_task.done():
            logger.warning("Automatic monitoring already running")
            return False
        
        if interval:
            self.auto_snapshot_interval = interval
        
        self.auto_snapshot_task = asyncio.create_task(self._auto_monitoring_loop())
        logger.info(f"Automatic monitoring started with {self.auto_snapshot_interval}s interval")
        return True
    
    async def stop_automatic_monitoring(self) -> bool:
        """
        Stop automatic periodic snapshot monitoring.
        
        Returns:
            True if monitoring stopped successfully
        """
        if self.auto_snapshot_task and not self.auto_snapshot_task.done():
            self.auto_snapshot_task.cancel()
            try:
                await self.auto_snapshot_task
            except asyncio.CancelledError:
                pass
            logger.info("Automatic monitoring stopped")
            return True
        
        return False
    
    async def _auto_monitoring_loop(self):
        """Internal automatic monitoring loop."""
        snapshot_counter = 0
        
        try:
            while True:
                await asyncio.sleep(self.auto_snapshot_interval)
                
                snapshot_name = f"auto_monitor_{int(time.time())}_{snapshot_counter}"
                
                if await self.snapshot_differ.create_snapshot(snapshot_name, {
                    "type": "automatic_monitoring",
                    "counter": snapshot_counter,
                    "interval": self.auto_snapshot_interval
                }):
                    
                    # Analyze changes if we have a baseline
                    if self.baseline_established:
                        analysis = await self.snapshot_differ.analyze_since_baseline(snapshot_name)
                        
                        # Check for significant changes
                        if analysis and self._has_significant_changes(analysis):
                            logger.info(f"Significant changes detected in automatic monitoring: {snapshot_name}")
                            
                            # Add to behavior timeline
                            timeline_entry = {
                                "snapshot_name": snapshot_name,
                                "timestamp": time.time(),
                                "type": "automatic_detection",
                                "analysis": analysis
                            }
                            self.behavior_timeline.append(timeline_entry)
                    
                    snapshot_counter += 1
                else:
                    logger.warning(f"Failed to create automatic monitoring snapshot: {snapshot_name}")
                
        except asyncio.CancelledError:
            logger.info("Automatic monitoring loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Error in automatic monitoring loop: {e}")
    
    def _has_significant_changes(self, analysis: Dict[str, Any]) -> bool:
        """Check if analysis results indicate significant changes."""
        if not analysis or 'statistics' not in analysis:
            return False
        
        stats = analysis['statistics']
        
        # Define thresholds for significant changes
        if stats.get('code_modifications', 0) > 0:
            return True
        if stats.get('regions_added', 0) > 5:
            return True
        if stats.get('heap_changes', 0) > 10:
            return True
        
        # Check license analysis confidence
        license_analysis = analysis.get('license_analysis', {})
        if license_analysis.get('confidence_score', 0) > 0.5:
            return True
        
        return False
    
    def _generate_execution_summary(self, execution_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of execution analysis results."""
        summary = {
            "total_checkpoints": len([r for r in execution_results.values() if isinstance(r, dict) and 'memory_changes' in r]),
            "significant_changes_detected": False,
            "license_activity_confidence": 0.0,
            "behavior_patterns": [],
            "security_concerns": []
        }
        
        # Analyze all checkpoint results
        for key, result in execution_results.items():
            if isinstance(result, dict) and 'license_analysis' in result:
                license_analysis = result['license_analysis']
                confidence = license_analysis.get('confidence_score', 0)
                summary["license_activity_confidence"] = max(summary["license_activity_confidence"], confidence)
                
                if confidence > 0.3:
                    summary["significant_changes_detected"] = True
                
                # Collect behavior patterns
                patterns = result.get('behavior_patterns', {})
                for pattern, detected in patterns.items():
                    if detected and pattern not in summary["behavior_patterns"]:
                        summary["behavior_patterns"].append(pattern)
                
                # Collect security concerns
                if patterns.get('self_modifying_code'):
                    summary["security_concerns"].append("Self-modifying code detected")
                if patterns.get('heap_spray'):
                    summary["security_concerns"].append("Potential heap spray attack")
                if patterns.get('code_injection'):
                    summary["security_concerns"].append("Code injection detected")
        
        return summary
    
    def _analyze_license_specific_behavior(self, pre_analysis: Optional[Dict[str, Any]],
                                         post_analysis: Optional[Dict[str, Any]],
                                         monitoring_data: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Analyze behavior specifically for license-related activity."""
        indicators = {
            "timing_analysis": {},
            "memory_patterns": {},
            "network_activity": {},
            "process_activity": {},
            "confidence_factors": []
        }
        
        if not post_analysis:
            return indicators
        
        # Timing analysis
        if pre_analysis and post_analysis:
            duration = post_analysis.get('timestamp2', 0) - pre_analysis.get('timestamp1', 0)
            indicators["timing_analysis"] = {
                "action_duration": duration,
                "suspicious_timing": duration > 5.0,  # Long license checks might indicate complex validation
                "rapid_execution": duration < 0.1     # Very fast might indicate bypass
            }
        
        # Memory pattern analysis
        license_analysis = post_analysis.get('license_analysis', {})
        indicators["memory_patterns"] = {
            "license_related_changes": license_analysis.get('license_check_detected', False),
            "protection_modifications": license_analysis.get('protection_circumvention', False),
            "confidence_score": license_analysis.get('confidence_score', 0.0)
        }
        
        # Network activity analysis
        network_changes = post_analysis.get('network_changes', {})
        indicators["network_activity"] = {
            "validation_attempts": len(network_changes.get('new_connections', [])),
            "license_server_contacted": any(
                conn.get('dst_port') in [27000, 1947, 443, 80] 
                for conn in network_changes.get('new_connections', [])
            )
        }
        
        # Process activity analysis
        process_changes = post_analysis.get('process_changes', {})
        license_processes = [
            proc for proc in process_changes.get('new_processes', [])
            if any(term in proc.get('name', '').lower() for term in ['license', 'activation', 'validation'])
        ]
        indicators["process_activity"] = {
            "license_processes_started": len(license_processes),
            "process_details": license_processes
        }
        
        # Calculate confidence factors
        if indicators["memory_patterns"]["license_related_changes"]:
            indicators["confidence_factors"].append("License-related memory changes detected")
        if indicators["network_activity"]["license_server_contacted"]:
            indicators["confidence_factors"].append("License server communication detected")
        if indicators["process_activity"]["license_processes_started"] > 0:
            indicators["confidence_factors"].append("License validation processes started")
        if indicators["timing_analysis"].get("suspicious_timing"):
            indicators["confidence_factors"].append("Suspicious timing patterns detected")
        
        return indicators
    
    def _generate_license_recommendations(self, license_analysis: Dict[str, Any]) -> List[str]:
        """Generate specific recommendations for license analysis results."""
        recommendations = []
        
        indicators = license_analysis.get('license_indicators', {})
        
        # Memory-based recommendations
        memory_patterns = indicators.get('memory_patterns', {})
        if memory_patterns.get('protection_modifications'):
            recommendations.append("Protection mechanism modifications detected - implement additional integrity checks")
        
        # Network-based recommendations
        network_activity = indicators.get('network_activity', {})
        if network_activity.get('license_server_contacted'):
            recommendations.append("License server communication detected - consider offline validation methods")
        
        # Process-based recommendations
        process_activity = indicators.get('process_activity', {})
        if process_activity.get('license_processes_started') > 0:
            recommendations.append("License validation processes detected - review process isolation")
        
        # Timing-based recommendations
        timing_analysis = indicators.get('timing_analysis', {})
        if timing_analysis.get('rapid_execution'):
            recommendations.append("Rapid execution detected - may indicate license check bypass")
        elif timing_analysis.get('suspicious_timing'):
            recommendations.append("Extended execution time - validate license check complexity")
        
        # General recommendations
        confidence_factors = indicators.get('confidence_factors', [])
        if len(confidence_factors) >= 3:
            recommendations.append("Multiple license indicators detected - comprehensive protection review recommended")
        
        return recommendations
    
    async def export_session_report(self, output_path: str, include_detailed_analysis: bool = True) -> bool:
        """
        Export comprehensive analysis session report.
        
        Args:
            output_path: Path for output report file
            include_detailed_analysis: Include detailed analysis data
            
        Returns:
            True if report exported successfully
        """
        if not self.analysis_session_id:
            logger.error("No active analysis session to export")
            return False
        
        try:
            report = {
                "session_metadata": {
                    "session_id": self.analysis_session_id,
                    "architecture": self.qemu_emulator.architecture,
                    "analysis_mode": self.analysis_mode,
                    "baseline_established": self.baseline_established,
                    "total_checkpoints": len(self.behavior_timeline),
                    "export_timestamp": time.time()
                },
                "behavior_timeline": self.behavior_timeline if include_detailed_analysis else [
                    {k: v for k, v in entry.items() if k != 'analysis'} 
                    for entry in self.behavior_timeline
                ],
                "session_summary": self._generate_session_summary(),
                "recommendations": self._generate_session_recommendations()
            }
            
            # Add snapshot information
            if self.snapshot_differ:
                report["snapshots"] = self.snapshot_differ.list_snapshots()
            
            import json
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Session report exported to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export session report: {e}")
            return False
    
    def _generate_session_summary(self) -> Dict[str, Any]:
        """Generate summary of the entire analysis session."""
        summary = {
            "total_duration": 0.0,
            "checkpoints_created": len(self.behavior_timeline),
            "significant_events": [],
            "license_activity_detected": False,
            "security_issues": [],
            "overall_confidence": 0.0
        }
        
        if not self.behavior_timeline:
            return summary
        
        # Calculate session duration
        first_checkpoint = min(entry['timestamp'] for entry in self.behavior_timeline)
        last_checkpoint = max(entry['timestamp'] for entry in self.behavior_timeline)
        summary["total_duration"] = last_checkpoint - first_checkpoint
        
        # Analyze all checkpoints for patterns
        max_confidence = 0.0
        for entry in self.behavior_timeline:
            analysis = entry.get('analysis', {})
            license_analysis = analysis.get('license_analysis', {})
            confidence = license_analysis.get('confidence_score', 0)
            max_confidence = max(max_confidence, confidence)
            
            if confidence > 0.3:
                summary["license_activity_detected"] = True
                summary["significant_events"].append({
                    "checkpoint": entry['checkpoint_name'],
                    "timestamp": entry['timestamp'],
                    "confidence": confidence,
                    "type": "license_activity"
                })
            
            # Check for security issues
            patterns = analysis.get('behavior_patterns', {})
            for pattern, detected in patterns.items():
                if detected and pattern not in [event.get('pattern') for event in summary["security_issues"]]:
                    summary["security_issues"].append({
                        "pattern": pattern,
                        "checkpoint": entry['checkpoint_name'],
                        "timestamp": entry['timestamp']
                    })
        
        summary["overall_confidence"] = max_confidence
        
        return summary
    
    def _generate_session_recommendations(self) -> List[str]:
        """Generate recommendations based on the entire session analysis."""
        recommendations = []
        
        session_summary = self._generate_session_summary()
        
        if session_summary["license_activity_detected"]:
            recommendations.append("License validation activity detected throughout session - review protection strategy")
        
        if len(session_summary["security_issues"]) > 0:
            recommendations.append(f"Multiple security patterns detected ({len(session_summary['security_issues'])}) - comprehensive security audit recommended")
        
        if session_summary["overall_confidence"] > 0.7:
            recommendations.append("High confidence license bypass activity - immediate protection enhancement required")
        
        if session_summary["checkpoints_created"] > 10:
            recommendations.append("Extensive analysis performed - consider implementing real-time monitoring")
        
        return recommendations
    
    async def cleanup(self):
        """Cleanup enhanced emulator resources."""
        try:
            # Stop automatic monitoring
            await self.stop_automatic_monitoring()
            
            # Cleanup snapshot differ
            if self.snapshot_differ:
                await self.snapshot_differ.cleanup()
            
            # Reset analysis state
            self.analysis_mode = False
            self.baseline_established = False
            self.analysis_session_id = None
            self.behavior_timeline = []
            
            logger.info("QEMUEmulatorEnhanced cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during enhanced emulator cleanup: {e}")


# Convenience function for creating enhanced emulator
async def create_enhanced_qemu_emulator(binary_path: str, architecture: str = 'x86_64',
                                      enable_analysis: bool = True) -> QEMUEmulatorEnhanced:
    """
    Create an enhanced QEMU emulator with snapshot diffing capabilities.
    
    Args:
        binary_path: Path to binary to analyze
        architecture: Target architecture
        enable_analysis: Whether to initialize analysis capabilities immediately
        
    Returns:
        Enhanced QEMU emulator instance
    """
    from .qemu_emulator import QEMUSystemEmulator
    
    # Create base emulator
    base_emulator = QEMUSystemEmulator(binary_path, architecture)
    
    # Wrap with enhanced capabilities
    enhanced_emulator = QEMUEmulatorEnhanced(base_emulator)
    
    # Initialize analysis if requested
    if enable_analysis:
        await enhanced_emulator.initialize_advanced_analysis()
    
    return enhanced_emulator


__all__ = [
    'QEMUEmulatorEnhanced',
    'create_enhanced_qemu_emulator'
]