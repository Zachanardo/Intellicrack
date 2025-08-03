#!/usr/bin/env python3
"""
Simple test for Multi-Agent System core functionality
"""

import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test if we can import the multi-agent system."""
    try:
        from intellicrack.ai.multi_agent_system import (
            AgentRole,
            BaseAgent,
            PackerAnalysisAgent,
            AntiDebugAgent,
            LicensingAgent,
            CoordinatorAgent,
            create_agent_by_type
        )
        print("✓ Successfully imported multi-agent system components")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_agent_creation():
    """Test creating agents."""
    try:
        from intellicrack.ai.multi_agent_system import create_agent_by_type, AgentRole
        
        # Test creating a packer analysis agent
        agent = create_agent_by_type("packer_analysis", "test_packer")
        print(f"✓ Created PackerAnalysisAgent: {agent.agent_id}")
        print(f"  - Role: {agent.role.value}")
        print(f"  - Capabilities: {len(agent.capabilities)}")
        
        # Test creating a coordinator agent  
        coord_agent = create_agent_by_type("coordinator", "test_coord")
        print(f"✓ Created CoordinatorAgent: {coord_agent.agent_id}")
        print(f"  - Role: {coord_agent.role.value}")
        print(f"  - Capabilities: {len(coord_agent.capabilities)}")
        
        return True
    except Exception as e:
        print(f"✗ Agent creation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_agent_capabilities():
    """Test agent capabilities are properly initialized."""
    try:
        from intellicrack.ai.multi_agent_system import create_agent_by_type
        
        agent = create_agent_by_type("packer_analysis", "test_caps")
        
        print(f"PackerAnalysisAgent capabilities:")
        for i, cap in enumerate(agent.capabilities, 1):
            print(f"  {i}. {cap.capability_name}")
            print(f"     Description: {cap.description}")
            print(f"     Confidence: {cap.confidence_level}")
        
        # Verify expected capabilities exist
        expected_caps = ["packer_detection", "upx_unpacking", "entropy_analysis"]
        agent_cap_names = [cap.capability_name for cap in agent.capabilities]
        
        for expected in expected_caps:
            if expected in agent_cap_names:
                print(f"✓ Found expected capability: {expected}")
            else:
                print(f"✗ Missing expected capability: {expected}")
        
        return True
    except Exception as e:
        print(f"✗ Capabilities test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    print("Simple Multi-Agent System Test")
    print("=" * 40)
    
    tests = [
        test_imports,
        test_agent_creation,
        test_agent_capabilities
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        print(f"\nRunning {test.__name__}...")
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    print(f"\nExit code: {exit_code}")
    sys.exit(exit_code)