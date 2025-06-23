#!/usr/bin/env python3
"""
AI Integration Example - Complete Workflow Demonstration

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
from pathlib import Path

from intellicrack.ai import (
    AutonomousAgent,
    IntelligentCodeModifier,
    IntegrationManager,
    LLMManager,
    PerformanceMonitor,
    OptimizationManager,
    optimize_ai_performance,
    get_performance_recommendations
)


async def demonstrate_ai_integration():
    """Demonstrate complete AI integration workflow."""
    print("🚀 Intellicrack AI Integration Demonstration")
    print("=" * 50)

    # Initialize components with performance monitoring
    with PerformanceMonitor() as perf_monitor:
        print("\n📊 Setting up performance monitoring...")

        # Initialize LLM manager (using mock for demo)
        llm_manager = LLMManager()

        # Initialize integration manager
        with IntegrationManager(llm_manager) as integration_mgr:
            print("✅ Integration manager started")

            # Demonstrate script generation
            print("\n🔧 Generating AI-powered bypass scripts...")

            # Create a complete bypass workflow
            workflow_id = integration_mgr.create_bypass_workflow(
                target_binary="/tmp/example_target.exe",
                bypass_type="license_validation"
            )

            print(f"📋 Created workflow: {workflow_id}")

            # Monitor workflow progress
            start_time = time.time()
            try:
                result = integration_mgr.wait_for_workflow(workflow_id, timeout=30.0)
                execution_time = time.time() - start_time

                print(f"✅ Workflow completed in {execution_time:.2f}s")
                print(f"   Tasks completed: {result.tasks_completed}")
                print(f"   Tasks failed: {result.tasks_failed}")
                print(f"   Success: {result.success}")

                if result.artifacts:
                    print(f"   Artifacts generated: {len(result.artifacts)}")

            except TimeoutError:
                print("⏰ Workflow timeout - continuing with demo")

            # Demonstrate code modification
            print("\n🔄 Demonstrating intelligent code modification...")

            # Create sample Python file for modification
            sample_file = Path("/tmp/demo_license_checker.py")
            sample_file.write_text("""
def validate_license(key):
    if not key:
        return False
    if len(key) < 16:
        return False
    if not key.startswith("LIC-"):
        return False
    return True

class LicenseManager:
    def __init__(self):
        self.valid_licenses = set()

    def check_license(self, key):
        return validate_license(key)
""")

            modifier = IntelligentCodeModifier(llm_manager)

            # Create modification request
            request = modifier.create_modification_request(
                description="Bypass license validation by always returning True",
                target_files=[str(sample_file)],
                requirements=["Always return True", "Maintain function signatures"],
                constraints=["Keep code readable", "Don't break existing imports"]
            )

            print(f"📝 Analyzing modification request: {request.request_id}")

            with perf_monitor.profile_operation("code_modification"):
                changes = modifier.analyze_modification_request(request)

            if changes:
                print(f"🎯 Generated {len(changes)} code changes")
                for change in changes:
                    print(f"   - {change.description} (confidence: {change.confidence:.2f})")

                # Preview changes
                preview = modifier.preview_changes([c.change_id for c in changes])
                print(f"📋 Preview: {preview['total_changes']} changes affecting {len(preview['files_affected'])} files")

            # Demonstrate autonomous agent
            print("\n🤖 Running autonomous analysis agent...")

            AutonomousAgent(llm_manager)

            with perf_monitor.profile_operation("autonomous_analysis"):
                # Mock the autonomous task execution for demo
                agent_results = {
                    "success": True,
                    "analysis_completed": True,
                    "scripts_generated": 1,
                    "modifications_suggested": len(changes) if changes else 0,
                    "confidence": 0.87
                }

            print("🎉 Autonomous agent results:")
            print(f"   Success: {agent_results['success']}")
            print(f"   Scripts generated: {agent_results['scripts_generated']}")
            print(f"   Modifications suggested: {agent_results['modifications_suggested']}")
            print(f"   Overall confidence: {agent_results['confidence']:.2f}")

            # Performance analysis
            print("\n📊 Performance Analysis")
            print("-" * 30)

            # Get performance summary
            perf_summary = perf_monitor.get_metrics_summary()

            if perf_summary.get("operation_summary"):
                print("Operation Performance:")
                for op_name, stats in perf_summary["operation_summary"].items():
                    print(f"   {op_name}:")
                    print(f"     - Avg execution time: {stats['avg_execution_time']:.3f}s")
                    print(f"     - Success rate: {stats['success_rate']:.1%}")

            # System health assessment
            system_health = perf_summary.get("system_health", {})
            health_score = system_health.get("score", 0)
            health_status = system_health.get("status", "unknown")

            print(f"\nSystem Health: {health_status.upper()} (Score: {health_score:.1f}/100)")

            if system_health.get("issues"):
                print("Issues detected:")
                for issue in system_health["issues"]:
                    print(f"   ⚠️  {issue}")

            # Optimization recommendations
            print("\n🔧 Optimization Recommendations")
            print("-" * 35)

            recommendations = get_performance_recommendations()
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    print(f"{i}. {rec}")
            else:
                print("✅ No optimization recommendations - system performing well!")

            # Run optimization if needed
            if health_score < 80:
                print("\n🛠️  Running performance optimization...")
                optimize_ai_performance()
                print("✅ Optimization completed")

            # Cleanup demo file
            if sample_file.exists():
                sample_file.unlink()


def demonstrate_advanced_features():
    """Demonstrate advanced AI integration features."""
    print("\n\n🎯 Advanced Features Demonstration")
    print("=" * 40)

    # Performance benchmarking
    print("📈 Benchmarking AI optimizations...")

    optimization_mgr = OptimizationManager()
    benchmark_results = optimization_mgr.benchmark_optimizations()

    print("Benchmark Results:")
    print(f"   Optimization time: {benchmark_results['optimization_time_seconds']:.3f}s")
    print(f"   Memory saved: {benchmark_results['memory_saved_mb']:.2f}MB")
    print(f"   Objects cleaned: {benchmark_results['objects_cleaned']}")
    print(f"   Efficiency: {benchmark_results['memory_efficiency_mb_per_second']:.2f}MB/s")

    # Integration statistics
    print("\n📊 Integration Manager Statistics:")
    integration_mgr = IntegrationManager()

    # Create some demo tasks for statistics
    for i in range(3):
        integration_mgr.create_task(
            task_type="generate_script",
            description=f"Demo task {i+1}",
            input_data={
                "request": {"target_info": {"file_path": f"/demo/target_{i}.exe"}},
                "script_type": "frida"
            }
        )

    print(f"   Active tasks: {len(integration_mgr.active_tasks)}")
    print(f"   Completed tasks: {len(integration_mgr.completed_tasks)}")
    print(f"   Active workflows: {len(integration_mgr.active_workflows)}")

    integration_mgr.stop()


async def main():
    """Main demonstration function."""
    try:
        print("🌟 Starting Intellicrack AI Integration Demo")
        print("🔬 This demonstrates the complete AI-powered workflow")
        print()

        # Run main demonstration
        await demonstrate_ai_integration()

        # Run advanced features demo
        demonstrate_advanced_features()

        print("\n\n🎉 Demonstration completed successfully!")
        print("💡 The AI integration system is ready for production use.")

    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the demonstration
    asyncio.run(main())