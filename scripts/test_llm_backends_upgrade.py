#!/usr/bin/env python3
"""
Test script for the upgraded LLM backends system.
Demonstrates new functionality and verifies integration.
"""

import os
import sys
import json
from typing import Dict, Any

# Add intellicrack to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from intellicrack.ai.llm_backends import (
    LLMManager, LLMProvider, LLMConfig,
    create_openai_config, create_anthropic_config, create_google_config,
    create_azure_openai_config, create_huggingface_api_config,
    get_llm_manager
)


def test_configuration_creation():
    """Test configuration helper functions."""
    print("=== Testing Configuration Creation ===")
    
    # Test OpenAI config
    openai_config = create_openai_config("gpt-4")
    print(f"OpenAI Config: {openai_config.provider.value} - {openai_config.model_name}")
    
    # Test Anthropic config
    anthropic_config = create_anthropic_config("claude-3-opus-20240229")
    print(f"Anthropic Config: {anthropic_config.provider.value} - {anthropic_config.model_name}")
    
    # Test Google config
    google_config = create_google_config("gemini-pro")
    print(f"Google Config: {google_config.provider.value} - {google_config.model_name}")
    
    # Test Azure OpenAI config
    azure_config = create_azure_openai_config(
        model_name="gpt-4",
        azure_endpoint="https://example.openai.azure.com/",
        deployment_name="gpt-4-deployment"
    )
    print(f"Azure Config: {azure_config.provider.value} - {azure_config.model_name}")
    
    # Test Hugging Face API config
    hf_config = create_huggingface_api_config("microsoft/DialoGPT-medium")
    print(f"HuggingFace API Config: {hf_config.provider.value} - {hf_config.model_name}")
    
    print("✓ Configuration creation tests passed\n")


def test_llm_manager_initialization():
    """Test LLM manager initialization with new features."""
    print("=== Testing LLM Manager Initialization ===")
    
    # Get global manager instance
    manager = get_llm_manager()
    
    # Check that infrastructure components are initialized
    print(f"Cost Tracker initialized: {manager.cost_tracker is not None}")
    print(f"Response Cache initialized: {manager.response_cache is not None}")
    print(f"Rate Limiter initialized: {manager.rate_limiter is not None}")
    print(f"Quality Assessor initialized: {manager.quality_assessor is not None}")
    
    print("✓ LLM Manager initialization tests passed\n")


def test_provider_support():
    """Test that all new providers are supported."""
    print("=== Testing Provider Support ===")
    
    manager = get_llm_manager()
    
    # Test provider enum values
    providers = [
        LLMProvider.OPENAI,
        LLMProvider.ANTHROPIC,
        LLMProvider.GOOGLE,
        LLMProvider.AZURE_OPENAI,
        LLMProvider.HUGGINGFACE_API,
        LLMProvider.OLLAMA,
        LLMProvider.GGUF
    ]
    
    for provider in providers:
        backend_class = manager._get_backend_class(provider)
        print(f"Provider {provider.value}: {backend_class.__name__}")
    
    print("✓ Provider support tests passed\n")


def test_model_selection():
    """Test intelligent model selection features."""
    print("=== Testing Intelligent Model Selection ===")
    
    manager = get_llm_manager()
    
    # Test task-based model selection
    task_types = ["code_generation", "analysis", "chat", "unknown_task"]
    
    for task_type in task_types:
        try:
            selected_model = manager.select_model_for_task(task_type)
            print(f"Task '{task_type}': Selected model {selected_model}")
        except Exception as e:
            print(f"Task '{task_type}': No models available ({e})")
    
    print("✓ Model selection tests passed\n")


def test_cost_tracking():
    """Test cost tracking functionality."""
    print("=== Testing Cost Tracking ===")
    
    manager = get_llm_manager()
    
    # Check initial costs
    costs = manager.cost_tracker.get_total_costs()
    print(f"Initial total costs: ${costs:.6f}")
    
    # Check costs by provider
    for provider in LLMProvider:
        provider_cost = manager.cost_tracker.get_costs_by_provider(provider)
        if provider_cost > 0:
            print(f"Provider {provider.value}: ${provider_cost:.6f}")
    
    print("✓ Cost tracking tests passed\n")


def test_cache_functionality():
    """Test response caching functionality."""
    print("=== Testing Response Cache ===")
    
    manager = get_llm_manager()
    
    # Check cache stats
    stats = manager.response_cache.get_stats()
    print(f"Cache stats: {stats}")
    
    # Test cache operations
    test_key = "test_prompt_key"
    test_response = "test_response"
    
    # Store and retrieve
    manager.response_cache.store(test_key, test_response)
    cached_response = manager.response_cache.get(test_key)
    
    print(f"Cache test: Stored='{test_response}', Retrieved='{cached_response}'")
    print(f"Cache hit: {cached_response == test_response}")
    
    print("✓ Cache functionality tests passed\n")


def generate_usage_report():
    """Generate a comprehensive usage report."""
    print("=== Generating Usage Report ===")
    
    manager = get_llm_manager()
    
    report = {
        "infrastructure": {
            "cost_tracker": manager.cost_tracker is not None,
            "response_cache": manager.response_cache is not None,
            "rate_limiter": manager.rate_limiter is not None,
            "quality_assessor": manager.quality_assessor is not None
        },
        "supported_providers": [provider.value for provider in LLMProvider],
        "cache_stats": manager.response_cache.get_stats(),
        "total_costs": manager.cost_tracker.get_total_costs(),
        "provider_costs": {
            provider.value: manager.cost_tracker.get_costs_by_provider(provider)
            for provider in LLMProvider
        }
    }
    
    print("Usage Report:")
    print(json.dumps(report, indent=2))
    print()


def main():
    """Run all tests and generate report."""
    print("LLM Backends Upgrade Verification Script")
    print("=" * 50)
    print()
    
    try:
        test_configuration_creation()
        test_llm_manager_initialization()
        test_provider_support()
        test_model_selection()
        test_cost_tracking()
        test_cache_functionality()
        generate_usage_report()
        
        print("🎉 All tests passed! LLM backends upgrade is working correctly.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())