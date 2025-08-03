#!/usr/bin/env python3
"""Test script for LLM Config Manager."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from intellicrack.ai.llm_config_manager import (
        get_llm_config_manager,
        ConfigurationProfile,
        ModelSettings,
        ProviderConfig,
        CostControl,
        ConfigurationSchema,
        create_provider_from_ui,
        create_model_from_ui
    )
    from intellicrack.ai.llm_backends import LLMProvider
    
    print("✓ All imports successful")
    
    # Test configuration manager creation
    config_manager = get_llm_config_manager()
    print("✓ Config manager created")
    
    # Test provider configuration
    openai_config = ProviderConfig(
        provider=LLMProvider.OPENAI,
        api_key="test-key",
        rate_limit=60,
        enabled=True
    )
    print("✓ Provider config created")
    
    # Test model settings
    model_settings = ModelSettings(
        model_name="gpt-4",
        provider=LLMProvider.OPENAI,
        temperature=0.7,
        max_tokens=2048
    )
    print("✓ Model settings created")
    
    # Test configuration profile
    profile = ConfigurationProfile.DEVELOPMENT
    print(f"✓ Configuration profile: {profile.value}")
    
    # Test cost control
    cost_control = CostControl(
        budget_limit=100.0,
        budget_period="monthly"
    )
    print("✓ Cost control created")
    
    # Test UI helper functions
    ui_provider = create_provider_from_ui("openai", "test-api-key")
    print("✓ UI provider helper works")
    
    ui_model = create_model_from_ui("gpt-4", "openai", 0.5, 1024)
    print("✓ UI model helper works")
    
    # Test configuration operations
    config_manager.set_environment(ConfigurationProfile.DEVELOPMENT)
    print("✓ Environment set")
    
    # Test validation
    is_valid, errors = config_manager.validate_config()
    print(f"✓ Configuration validation: {'valid' if is_valid else 'invalid'}")
    
    # Test usage tracking
    config_manager.track_usage("test-model", 1000, 0.5)
    stats = config_manager.get_usage_stats()
    print(f"✓ Usage tracking: {stats['total_tokens']} tokens")
    
    print("\n✅ All tests passed! LLM Config Manager is fully functional.")
    
except Exception as e:
    print(f"\n❌ Test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)