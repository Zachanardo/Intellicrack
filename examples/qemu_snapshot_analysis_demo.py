"""
QEMU Snapshot Analysis Demo Script.

Demonstrates the comprehensive QEMU snapshot diffing system for runtime
behavior analysis and license detection in security research environments.

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
import json
import sys
import time
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.core.processing.qemu_emulator import QEMUSystemEmulator
from intellicrack.core.processing.qemu_integration_layer import create_enhanced_qemu_emulator


async def demo_basic_snapshot_diffing():
    """Demonstrate basic snapshot diffing capabilities."""
    print("=== Basic QEMU Snapshot Diffing Demo ===\n")
    
    # Create enhanced QEMU emulator for a test binary
    test_binary = Path("C:/Windows/System32/calc.exe")  # Example binary
    if not test_binary.exists():
        print("Test binary not found. Using placeholder path.")
        test_binary = "/path/to/test/binary.exe"
    
    try:
        enhanced_emulator = await create_enhanced_qemu_emulator(
            str(test_binary), 
            architecture="x86_64",
            enable_analysis=True
        )
        
        print("✓ Enhanced QEMU emulator created successfully")
        
        # Start behavior analysis session
        session_id = await enhanced_emulator.start_behavior_analysis_session("license_analysis_demo")
        
        if session_id:
            print(f"✓ Analysis session started: {session_id}")
            
            # Simulate taking checkpoints during analysis
            print("\n--- Taking Analysis Checkpoints ---")
            
            checkpoint1 = await enhanced_emulator.take_analysis_checkpoint(
                "initial_state",
                {"description": "System initial state before any action"}
            )
            
            if checkpoint1:
                print("✓ Initial checkpoint created")
                print(f"  - Memory changes detected: {checkpoint1.get('memory_changes', {}).get('total_changes', 0)}")
                print(f"  - License confidence: {checkpoint1.get('license_analysis', {}).get('confidence_score', 0.0):.2f}")
            
            # Simulate some time passing and system changes
            await asyncio.sleep(2)
            
            checkpoint2 = await enhanced_emulator.take_analysis_checkpoint(
                "post_action_state",
                {"description": "System state after simulated action"}
            )
            
            if checkpoint2:
                print("✓ Post-action checkpoint created")
                print(f"  - Memory changes detected: {checkpoint2.get('memory_changes', {}).get('total_changes', 0)}")
                print(f"  - License confidence: {checkpoint2.get('license_analysis', {}).get('confidence_score', 0.0):.2f}")
            
            # Export session report
            report_path = Path("qemu_analysis_demo_report.json")
            if await enhanced_emulator.export_session_report(str(report_path)):
                print(f"✓ Session report exported to: {report_path}")
            
        else:
            print("✗ Failed to start analysis session")
        
        # Cleanup
        await enhanced_emulator.cleanup()
        print("✓ Cleanup completed")
        
    except Exception as e:
        print(f"✗ Demo failed: {e}")


async def demo_license_check_analysis():
    """Demonstrate license check analysis workflow."""
    print("\n=== License Check Analysis Demo ===\n")
    
    test_binary = Path("C:/Windows/System32/notepad.exe")  # Example binary
    if not test_binary.exists():
        print("Test binary not found. Using placeholder path.")
        test_binary = "/path/to/licensed/software.exe"
    
    try:
        enhanced_emulator = await create_enhanced_qemu_emulator(
            str(test_binary),
            architecture="x86_64", 
            enable_analysis=True
        )
        
        print("✓ Enhanced emulator ready for license analysis")
        
        # Define a mock license check action
        async def mock_license_check():
            """Simulate triggering a license check in the software."""
            print("  Simulating license check trigger...")
            await asyncio.sleep(1)  # Simulate processing time
            return {"status": "license_check_triggered"}
        
        # Analyze the license check sequence
        license_analysis = await enhanced_emulator.analyze_license_check_sequence(
            mock_license_check,
            "startup_license_validation"
        )
        
        if license_analysis and "error" not in license_analysis:
            print("✓ License check analysis completed")
            
            indicators = license_analysis.get("license_indicators", {})
            print(f"\n--- License Analysis Results ---")
            print(f"Action Duration: {license_analysis.get('total_duration', 0):.2f}s")
            
            timing = indicators.get("timing_analysis", {})
            if timing:
                print(f"License Check Duration: {timing.get('action_duration', 0):.2f}s")
                print(f"Suspicious Timing: {timing.get('suspicious_timing', False)}")
            
            memory_patterns = indicators.get("memory_patterns", {})
            if memory_patterns:
                print(f"License Changes Detected: {memory_patterns.get('license_related_changes', False)}")
                print(f"Protection Modifications: {memory_patterns.get('protection_modifications', False)}")
                print(f"Confidence Score: {memory_patterns.get('confidence_score', 0.0):.2f}")
            
            recommendations = license_analysis.get("recommendations", [])
            if recommendations:
                print(f"\n--- Recommendations ---")
                for i, rec in enumerate(recommendations, 1):
                    print(f"{i}. {rec}")
        else:
            print("✗ License check analysis failed")
            if license_analysis and "error" in license_analysis:
                print(f"Error: {license_analysis['error']}")
        
        await enhanced_emulator.cleanup()
        
    except Exception as e:
        print(f"✗ License analysis demo failed: {e}")


async def demo_real_time_monitoring():
    """Demonstrate real-time behavior monitoring."""
    print("\n=== Real-Time Monitoring Demo ===\n")
    
    test_binary = Path("C:/Windows/System32/cmd.exe")  # Example binary
    if not test_binary.exists():
        print("Test binary not found. Using placeholder path.")
        test_binary = "/path/to/monitored/application.exe"
    
    try:
        enhanced_emulator = await create_enhanced_qemu_emulator(
            str(test_binary),
            architecture="x86_64",
            enable_analysis=True
        )
        
        print("✓ Starting real-time monitoring demo")
        
        # Start automatic monitoring with 5-second intervals
        if await enhanced_emulator.start_automatic_monitoring(interval=5.0):
            print("✓ Automatic monitoring started (5s intervals)")
            
            # Let monitoring run for 20 seconds
            print("Running monitoring for 20 seconds...")
            await asyncio.sleep(20)
            
            # Stop monitoring
            if await enhanced_emulator.stop_automatic_monitoring():
                print("✓ Automatic monitoring stopped")
                
                # Check behavior timeline
                timeline = enhanced_emulator.behavior_timeline
                print(f"Captured {len(timeline)} monitoring events")
                
                if timeline:
                    print("\n--- Monitoring Timeline ---")
                    for i, event in enumerate(timeline[-3:], 1):  # Show last 3 events
                        print(f"{i}. {event.get('type', 'unknown')} at {time.ctime(event.get('timestamp', 0))}")
                        
                        analysis = event.get('analysis')
                        if analysis:
                            stats = analysis.get('statistics', {})
                            print(f"   Changes: {stats.get('total_changes', 0)}")
            else:
                print("✗ Failed to stop monitoring")
        else:
            print("✗ Failed to start automatic monitoring")
        
        await enhanced_emulator.cleanup()
        
    except Exception as e:
        print(f"✗ Real-time monitoring demo failed: {e}")


async def demo_execution_with_analysis():
    """Demonstrate binary execution with comprehensive analysis."""
    print("\n=== Execution with Analysis Demo ===\n")
    
    test_binary = Path("C:/Windows/System32/ping.exe")  # Example binary
    if not test_binary.exists():
        print("Test binary not found. Using placeholder path.")
        test_binary = "/path/to/analyzed/binary.exe"
    
    try:
        enhanced_emulator = await create_enhanced_qemu_emulator(
            str(test_binary),
            architecture="x86_64",
            enable_analysis=True
        )
        
        print("✓ Prepared for execution analysis")
        
        # Execute binary with comprehensive monitoring
        execution_results = await enhanced_emulator.execute_with_analysis(
            str(test_binary),
            pre_execution_checkpoint=True,
            post_execution_checkpoint=True,
            monitor_during_execution=True
        )
        
        if "error" not in execution_results:
            print("✓ Execution analysis completed")
            
            summary = execution_results.get("summary", {})
            print(f"\n--- Execution Summary ---")
            print(f"Total Duration: {execution_results.get('total_duration', 0):.2f}s")
            print(f"Checkpoints Created: {summary.get('total_checkpoints', 0)}")
            print(f"Significant Changes: {summary.get('significant_changes_detected', False)}")
            print(f"License Activity Confidence: {summary.get('license_activity_confidence', 0.0):.2f}")
            
            patterns = summary.get("behavior_patterns", [])
            if patterns:
                print(f"Behavior Patterns: {', '.join(patterns)}")
            
            concerns = summary.get("security_concerns", [])
            if concerns:
                print(f"Security Concerns: {', '.join(concerns)}")
            
            # Export detailed execution report
            exec_report_path = Path("execution_analysis_report.json")
            with open(exec_report_path, 'w') as f:
                json.dump(execution_results, f, indent=2, default=str)
            print(f"✓ Detailed report saved to: {exec_report_path}")
            
        else:
            print("✗ Execution analysis failed")
            print(f"Error: {execution_results['error']}")
        
        await enhanced_emulator.cleanup()
        
    except Exception as e:
        print(f"✗ Execution analysis demo failed: {e}")


async def demo_snapshot_management():
    """Demonstrate advanced snapshot management features."""
    print("\n=== Snapshot Management Demo ===\n")
    
    test_binary = Path("C:/Windows/System32/svchost.exe")  # Example binary
    if not test_binary.exists():
        print("Test binary not found. Using placeholder path.")
        test_binary = "/path/to/test/binary.exe"
    
    try:
        enhanced_emulator = await create_enhanced_qemu_emulator(
            str(test_binary),
            architecture="x86_64",
            enable_analysis=True
        )
        
        print("✓ Enhanced emulator ready for snapshot management demo")
        
        if enhanced_emulator.snapshot_differ:
            differ = enhanced_emulator.snapshot_differ
            
            # Create several test snapshots
            snapshots_to_create = [
                ("baseline_state", {"type": "baseline", "description": "Initial system state"}),
                ("loaded_binary", {"type": "loaded", "description": "After binary loading"}),
                ("executing_state", {"type": "execution", "description": "During execution"}),
                ("final_state", {"type": "final", "description": "After execution complete"})
            ]
            
            print("Creating test snapshots...")
            created_snapshots = []
            
            for name, annotations in snapshots_to_create:
                if await differ.create_snapshot(name, annotations):
                    created_snapshots.append(name)
                    print(f"✓ Created snapshot: {name}")
                    await asyncio.sleep(1)  # Brief pause between snapshots
                else:
                    print(f"✗ Failed to create snapshot: {name}")
            
            # List all snapshots
            snapshots_list = differ.list_snapshots()
            print(f"\n--- Available Snapshots ({len(snapshots_list)}) ---")
            for snapshot in snapshots_list:
                print(f"• {snapshot['name']} - {snapshot['architecture']} - {time.ctime(snapshot['timestamp'])}")
            
            # Demonstrate snapshot comparison
            if len(created_snapshots) >= 2:
                snapshot1, snapshot2 = created_snapshots[0], created_snapshots[-1]
                print(f"\n--- Comparing {snapshot1} vs {snapshot2} ---")
                
                diff_result = await differ.diff_snapshots(snapshot1, snapshot2)
                
                if "error" not in diff_result:
                    stats = diff_result.get("statistics", {})
                    print(f"Duration between snapshots: {diff_result.get('duration', 0):.2f}s")
                    print(f"Total changes: {stats.get('diff_duration', 0):.2f}s analysis time")
                    print(f"Regions added: {stats.get('regions_added', 0)}")
                    print(f"Regions removed: {stats.get('regions_removed', 0)}")
                    print(f"Code modifications: {stats.get('code_modifications', 0)}")
                    print(f"Heap changes: {stats.get('heap_changes', 0)}")
                    
                    # Export comparison report
                    comparison_report = Path("snapshot_comparison_report.json")
                    if await differ.export_analysis_report(snapshot1, snapshot2, str(comparison_report)):
                        print(f"✓ Comparison report exported: {comparison_report}")
                else:
                    print(f"✗ Snapshot comparison failed: {diff_result['error']}")
            
            # Clean up test snapshots
            print(f"\nCleaning up {len(created_snapshots)} test snapshots...")
            for snapshot_name in created_snapshots:
                if await differ.delete_snapshot(snapshot_name):
                    print(f"✓ Deleted: {snapshot_name}")
                else:
                    print(f"✗ Failed to delete: {snapshot_name}")
        
        await enhanced_emulator.cleanup()
        
    except Exception as e:
        print(f"✗ Snapshot management demo failed: {e}")


def print_system_requirements():
    """Print system requirements and setup information."""
    print("=== QEMU Snapshot Analysis System Requirements ===\n")
    print("Hardware Requirements:")
    print("• CPU: Multi-core processor with virtualization support")
    print("• RAM: Minimum 8GB, recommended 16GB+")
    print("• Storage: 50GB+ free space for snapshots")
    print("• Network: Internet connection for license server simulation")
    
    print("\nSoftware Requirements:")
    print("• QEMU 6.0+ with QMP support")
    print("• Python 3.8+ with asyncio support")
    print("• Windows 10+ or Linux with KVM support")
    
    print("\nSecurity Research Environment:")
    print("• Isolated network for malware analysis")
    print("• VM snapshots for safe rollback")
    print("• Monitoring tools for behavior analysis")
    
    print("\nLegal Notice:")
    print("• This tool is for authorized security research only")
    print("• Only analyze software you own or have permission to test")
    print("• Use in controlled, isolated environments")
    print("• Comply with all applicable laws and regulations")


async def main():
    """Main demo orchestration function."""
    print("QEMU Snapshot Diffing System - Comprehensive Demo")
    print("=" * 55)
    
    # Print requirements
    print_system_requirements()
    
    # Run demo scenarios
    try:
        await demo_basic_snapshot_diffing()
        await demo_license_check_analysis()
        await demo_real_time_monitoring()
        await demo_execution_with_analysis()
        await demo_snapshot_management()
        
        print("\n" + "=" * 55)
        print("✓ All demos completed successfully!")
        print("\nGenerated Reports:")
        
        reports = [
            "qemu_analysis_demo_report.json",
            "execution_analysis_report.json", 
            "snapshot_comparison_report.json"
        ]
        
        for report in reports:
            if Path(report).exists():
                print(f"• {report}")
        
        print("\nFor production use:")
        print("1. Configure QEMU with appropriate VM images")
        print("2. Set up isolated network environment")
        print("3. Implement proper logging and monitoring")
        print("4. Review and customize analysis thresholds")
        print("5. Integrate with existing security tools")
        
    except KeyboardInterrupt:
        print("\n✗ Demo interrupted by user")
    except Exception as e:
        print(f"\n✗ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the comprehensive demo
    asyncio.run(main())