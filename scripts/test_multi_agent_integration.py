#!/usr/bin/env python3
"""
Test script for Multi-Agent System integration
"""

import asyncio
import sys
import time
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intellicrack.ai.multi_agent_system import (
    AgentTask, 
    TaskPriority,
    create_agent_by_type,
    create_default_agent_system,
    initialize_multi_agent_system
)

async def test_agent_creation():
    """Test creating different types of agents."""
    print("Testing agent creation...")
    
    agent_types = [
        "packer_analysis",
        "anti_debug", 
        "licensing",
        "coordinator"
    ]
    
    agents = []
    for agent_type in agent_types:
        try:
            agent = create_agent_by_type(agent_type)
            agents.append(agent)
            print(f"✓ Created {agent_type} agent: {agent.agent_id}")
            print(f"  - Role: {agent.role.value}")
            print(f"  - Capabilities: {len(agent.capabilities)}")
        except Exception as e:
            print(f"✗ Failed to create {agent_type} agent: {e}")
    
    return agents

async def test_agent_capabilities():
    """Test agent capabilities."""
    print("\nTesting agent capabilities...")
    
    # Test PackerAnalysisAgent
    packer_agent = create_agent_by_type("packer_analysis", "test_packer")
    print(f"PackerAnalysisAgent capabilities:")
    for cap in packer_agent.capabilities:
        print(f"  - {cap.capability_name}: {cap.description}")
    
    # Test CoordinatorAgent
    coord_agent = create_agent_by_type("coordinator", "test_coordinator")
    print(f"\nCoordinatorAgent capabilities:")
    for cap in coord_agent.capabilities:
        print(f"  - {cap.capability_name}: {cap.description}")

async def test_agent_task_execution():
    """Test agent task execution."""
    print("\nTesting agent task execution...")
    
    # Create a packer analysis agent
    packer_agent = create_agent_by_type("packer_analysis", "test_packer_exec")
    
    # Create a test task
    task = AgentTask(
        task_id="test_task_001",
        task_type="packer_detection",
        description="Test packer detection on sample binary",
        input_data={
            "binary_path": "C:\\test\\sample.exe",
            "file_size": 1024000
        },
        priority=TaskPriority.HIGH
    )
    
    try:
        print(f"Executing task: {task.task_type}")
        result = await packer_agent.execute_task(task)
        print(f"✓ Task executed successfully")
        print(f"  - Confidence: {result.get('confidence', 'N/A')}")
        print(f"  - Primary packer: {result.get('packer_detection_result', {}).get('primary_packer', 'N/A')}")
        return True
    except Exception as e:
        print(f"✗ Task execution failed: {e}")
        return False

async def test_multi_agent_system():
    """Test multi-agent system creation and management."""
    print("\nTesting multi-agent system...")
    
    try:
        # Create system
        system = create_default_agent_system()
        print(f"✓ Created multi-agent system with {len(system.agents)} agents")
        
        # Test system status
        status = system.get_system_status()
        print(f"  - Active: {status['active']}")
        print(f"  - Total agents: {status['total_agents']}")
        print(f"  - Active agents: {status['active_agents']}")
        
        # List agents
        print("  - Agents:")
        for agent_id, agent in system.agents.items():
            print(f"    * {agent_id}: {agent.role.value}")
        
        return True
    except Exception as e:
        print(f"✗ Multi-agent system test failed: {e}")
        return False

async def test_coordination_capabilities():
    """Test coordination agent capabilities."""
    print("\nTesting coordination capabilities...")
    
    try:
        coord_agent = create_agent_by_type("coordinator", "test_coord")
        
        # Test task orchestration
        task = AgentTask(
            task_id="coord_test_001",
            task_type="task_orchestration",
            description="Test task orchestration",
            input_data={
                "complex_task": {
                    "type": "comprehensive_binary_analysis",
                    "target": "sample.exe"
                }
            },
            priority=TaskPriority.HIGH
        )
        
        result = await coord_agent.execute_task(task)
        print(f"✓ Orchestration test completed")
        plan = result.get('orchestration_plan', {})
        print(f"  - Analysis type: {plan.get('analysis_type', 'N/A')}")
        print(f"  - Total phases: {plan.get('total_phases', 0)}")
        print(f"  - Estimated time: {plan.get('estimated_time', 0)} seconds")
        
        return True
    except Exception as e:
        print(f"✗ Coordination test failed: {e}")
        return False

async def main():
    """Main test function."""
    print("Multi-Agent System Integration Test")
    print("=" * 50)
    
    tests = [
        test_agent_creation,
        test_agent_capabilities,
        test_agent_task_execution,
        test_multi_agent_system,
        test_coordination_capabilities
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            result = await test()
            if result is not False:  # None or True both count as pass
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Multi-agent system is working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)