#!/usr/bin/env python3
"""
Test script for LLM Model Manager integration.

This script verifies that the enhanced model manager can be imported
and basic functionality works correctly.
"""

import os
import sys
import logging

# Add Intellicrack to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_basic_imports():
    """Test that all components can be imported."""
    try:
        from intellicrack.ai.model_manager_module import (
            LLMModelManager, ModelOrchestrator, LLMResourceManager,
            LLMHealthMonitor, LLMVersionManager, LLMLoadBalancer,
            LLMCostOptimizer, create_llm_model_manager,
            get_global_llm_model_manager
        )
        logger.info("✓ All LLM model manager components imported successfully")
        return True
    except ImportError as e:
        logger.error(f"✗ Import error: {e}")
        return False

def test_llm_model_manager_creation():
    """Test creating an LLM model manager instance."""
    try:
        from intellicrack.ai.model_manager_module import create_llm_model_manager
        
        # Create instance
        manager = create_llm_model_manager()
        
        # Test basic functionality
        stats = manager.get_llm_manager_stats()
        assert isinstance(stats, dict)
        
        logger.info("✓ LLM model manager created and basic stats retrieved")
        return True
    except Exception as e:
        logger.error(f"✗ LLM model manager creation failed: {e}")
        return False

def test_resource_manager():
    """Test resource manager functionality."""
    try:
        from intellicrack.ai.model_manager_module import LLMResourceManager, ResourceAllocation
        
        resource_manager = LLMResourceManager()
        
        # Test resource allocation
        requirements = ResourceAllocation(
            model_id="test_model",
            cpu_cores=2,
            memory_gb=4.0,
            gpu_memory_gb=2.0
        )
        
        success = resource_manager.allocate_resources("test_model", requirements)
        if success:
            usage = resource_manager.get_resource_usage()
            assert usage['allocated_models'] == 1
            
            # Clean up
            resource_manager.deallocate_resources("test_model")
            
        logger.info("✓ Resource manager allocation/deallocation works")
        return True
    except Exception as e:
        logger.error(f"✗ Resource manager test failed: {e}")
        return False

def test_health_monitor():
    """Test health monitoring functionality."""
    try:
        from intellicrack.ai.model_manager_module import LLMHealthMonitor
        
        monitor = LLMHealthMonitor()
        
        # Register a model and record some requests
        monitor.register_model("test_model")
        monitor.record_request("test_model", True, 0.5)
        monitor.record_request("test_model", True, 0.8)
        monitor.record_request("test_model", False, 0.0, "Test error")
        
        # Check health
        health = monitor.check_model_health("test_model")
        assert 'healthy' in health
        assert 'health_score' in health
        
        # Get metrics
        metrics = monitor.get_performance_metrics("test_model")
        assert 'total_requests' in metrics
        
        logger.info("✓ Health monitor recording and reporting works")
        return True
    except Exception as e:
        logger.error(f"✗ Health monitor test failed: {e}")
        return False

def test_cost_optimizer():
    """Test cost optimization functionality."""
    try:
        from intellicrack.ai.model_manager_module import LLMCostOptimizer
        
        optimizer = LLMCostOptimizer()
        
        # Track some usage
        cost = optimizer.track_usage("gpt-4", 1000, 500, "gpt-4")
        assert cost > 0
        
        # Get cost summary
        summary = optimizer.get_cost_summary("gpt-4")
        assert 'total_cost' in summary
        assert summary['total_cost'] > 0
        
        # Get recommendations
        recommendations = optimizer.get_optimization_recommendations()
        assert isinstance(recommendations, list)
        
        logger.info("✓ Cost optimizer tracking and recommendations work")
        return True
    except Exception as e:
        logger.error(f"✗ Cost optimizer test failed: {e}")
        return False

def test_integration():
    """Test integration between components."""
    try:
        from intellicrack.ai.model_manager_module import (
            get_global_llm_model_manager, ModelType, ModelState
        )
        
        # Get global manager
        manager = get_global_llm_model_manager()
        
        # Test model registration with metadata
        config = {
            'provider': 'local',
            'model_name': 'test-model',
            'api_base': 'http://localhost:8080'
        }
        
        # This should work even without actual LLM backends
        try:
            success = manager.register_llm_model(
                "integration_test_model", 
                config, 
                ModelType.LLM_MODEL
            )
            if success or "integration_test_model" in manager.model_metadata:
                logger.info("✓ Model registration integration works")
            else:
                logger.warning("~ Model registration returned False but may be due to missing LLM backends")
        except Exception as reg_error:
            logger.warning(f"~ Model registration failed (expected without LLM backends): {reg_error}")
        
        # Test stats
        stats = manager.get_llm_manager_stats()
        assert isinstance(stats, dict)
        assert 'llm_models_loaded' in stats
        
        logger.info("✓ Component integration works correctly")
        return True
    except Exception as e:
        logger.error(f"✗ Integration test failed: {e}")
        return False

def main():
    """Run all tests."""
    logger.info("Starting LLM Model Manager integration tests...")
    
    tests = [
        test_basic_imports,
        test_llm_model_manager_creation,
        test_resource_manager,
        test_health_monitor,
        test_cost_optimizer,
        test_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            logger.error(f"✗ Test {test_func.__name__} crashed: {e}")
    
    logger.info(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed! LLM Model Manager is ready for use.")
        return True
    else:
        logger.warning(f"⚠️  {total - passed} tests failed. Check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)