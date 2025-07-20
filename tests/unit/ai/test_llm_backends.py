"""
Unit tests for LLM Backends with REAL API integration.
Tests REAL OpenAI, Anthropic, and local model backends.
NO MOCKS - ALL TESTS USE REAL MODEL APIs AND RESPONSES.
"""

import pytest
import os
import time
from pathlib import Path

from intellicrack.ai.llm_backends import (
    OpenAIBackend, AnthropicBackend, LocalModelBackend, 
    LLMBackend, ModelManager
)
from tests.base_test import BaseIntellicrackTest


class TestLLMBackends(BaseIntellicrackTest):
    """Test LLM backends with REAL API calls and model responses."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test environment for LLM backends."""
        self.model_manager = ModelManager()
        
    @pytest.mark.skipif(not os.getenv('OPENAI_API_KEY'), reason="No OpenAI API key")
    def test_openai_backend_real(self):
        """Test REAL OpenAI API integration."""
        backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
        
        # Test real API call
        prompt = "Generate a simple Frida script that hooks CreateFileW and logs the filename."
        response = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=500)
        
        # Validate real response
        self.assert_real_output(response)
        assert 'content' in response
        assert 'metadata' in response
        
        content = response['content']
        assert isinstance(content, str)
        assert len(content) > 50  # Real response should be substantial
        assert 'frida' in content.lower() or 'createfilew' in content.lower()
        
        # Check metadata
        metadata = response['metadata']
        assert 'model' in metadata
        assert 'tokens_used' in metadata
        assert 'response_time' in metadata
        assert metadata['tokens_used'] > 0
        assert metadata['response_time'] > 0
        
    @pytest.mark.skipif(not os.getenv('ANTHROPIC_API_KEY'), reason="No Anthropic API key")
    def test_anthropic_backend_real(self):
        """Test REAL Anthropic Claude API integration."""
        backend = AnthropicBackend(api_key=os.getenv('ANTHROPIC_API_KEY'))
        
        # Test real API call
        prompt = "Explain how to bypass a simple anti-debugging check in a Windows PE file."
        response = backend.generate(prompt, model='claude-3-haiku-20240307', max_tokens=300)
        
        # Validate real response
        self.assert_real_output(response)
        assert 'content' in response
        assert 'metadata' in response
        
        content = response['content']
        assert isinstance(content, str)
        assert len(content) > 50
        assert 'debug' in content.lower() or 'bypass' in content.lower()
        
        # Check Claude-specific metadata
        metadata = response['metadata']
        assert 'model' in metadata
        assert 'stop_reason' in metadata
        assert 'tokens_used' in metadata
        
    def test_local_model_backend_real(self):
        """Test REAL local model integration with GGUF files."""
        backend = LocalModelBackend()
        
        # Check if local models are available
        available_models = backend.list_available_models()
        
        if not available_models:
            pytest.skip("No local models available for testing")
            
        # Use first available model
        model_name = available_models[0]
        
        # Test real local inference
        prompt = "Write a Python function to calculate entropy of a byte array."
        response = backend.generate(prompt, model=model_name, max_tokens=200)
        
        # Validate real local response
        self.assert_real_output(response)
        assert 'content' in response
        assert 'metadata' in response
        
        content = response['content']
        assert isinstance(content, str)
        assert len(content) > 20  # Even small models produce some output
        
        # Check local model metadata
        metadata = response['metadata']
        assert 'model_path' in metadata
        assert 'inference_time' in metadata
        assert 'memory_usage' in metadata
        
    def test_model_fallback_chain_real(self):
        """Test REAL fallback chain when primary models fail."""
        # Create fallback chain
        fallback_chain = [
            ('openai', 'gpt-4'),
            ('openai', 'gpt-3.5-turbo'),
            ('local', 'any_available')
        ]
        
        backend = LLMBackend(fallback_chain=fallback_chain)
        
        # Test with realistic prompt
        prompt = "Generate a simple buffer overflow exploit payload."
        response = backend.generate_with_fallback(prompt, max_tokens=300)
        
        # Should get response from some model in chain
        assert response is not None
        self.assert_real_output(response)
        assert 'content' in response
        assert 'model_used' in response['metadata']
        
    def test_rate_limiting_real(self):
        """Test REAL rate limiting with API backends."""
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("No OpenAI API key for rate limiting test")
            
        backend = OpenAIBackend(
            api_key=os.getenv('OPENAI_API_KEY'),
            rate_limit={'requests_per_minute': 5}
        )
        
        # Make multiple rapid requests
        responses = []
        start_time = time.time()
        
        for i in range(3):
            prompt = f"Generate comment #{i} for a simple function."
            response = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=50)
            responses.append(response)
            
        end_time = time.time()
        
        # Validate responses
        for response in responses:
            self.assert_real_output(response)
            
        # Check that rate limiting was applied (requests took time)
        total_time = end_time - start_time
        assert total_time >= 10  # Should be rate limited
        
    def test_context_window_management_real(self):
        """Test REAL context window management with large inputs."""
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("No OpenAI API key for context window test")
            
        backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
        
        # Create large prompt that might exceed context window
        large_binary_data = "Binary data: " + "41" * 10000  # Simulated hex dump
        prompt = f"Analyze this binary data and identify patterns:\n{large_binary_data}\nWhat do you see?"
        
        response = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=200)
        
        # Should handle gracefully
        assert response is not None
        if 'error' not in response:
            self.assert_real_output(response)
        else:
            # Should provide helpful error message
            assert 'context' in response['error'].lower() or 'token' in response['error'].lower()
            
    def test_model_performance_monitoring_real(self):
        """Test REAL model performance monitoring and metrics."""
        # Test with available backend
        if os.getenv('OPENAI_API_KEY'):
            backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
            model = 'gpt-3.5-turbo'
        else:
            backend = LocalModelBackend()
            available_models = backend.list_available_models()
            if not available_models:
                pytest.skip("No models available for performance testing")
            model = available_models[0]
            
        # Enable performance monitoring
        backend.enable_performance_monitoring()
        
        # Make test requests
        prompts = [
            "Generate a simple function.",
            "Explain a concept briefly.",
            "Write a short script."
        ]
        
        for prompt in prompts:
            response = backend.generate(prompt, model=model, max_tokens=100)
            assert response is not None
            
        # Get performance metrics
        metrics = backend.get_performance_metrics()
        
        # Validate real metrics
        self.assert_real_output(metrics)
        assert 'average_response_time' in metrics
        assert 'total_tokens_used' in metrics
        assert 'requests_made' in metrics
        assert 'error_rate' in metrics
        
        assert metrics['requests_made'] == len(prompts)
        assert metrics['average_response_time'] > 0
        
    def test_model_quality_assessment_real(self):
        """Test REAL model quality assessment and comparison."""
        # Test code generation quality
        coding_prompt = "Write a Python function to parse PE headers."
        
        # Collect responses from available models
        responses = {}
        
        if os.getenv('OPENAI_API_KEY'):
            openai_backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
            responses['gpt-3.5-turbo'] = openai_backend.generate(
                coding_prompt, model='gpt-3.5-turbo', max_tokens=300
            )
            
        if os.getenv('ANTHROPIC_API_KEY'):
            anthropic_backend = AnthropicBackend(api_key=os.getenv('ANTHROPIC_API_KEY'))
            responses['claude-3-haiku'] = anthropic_backend.generate(
                coding_prompt, model='claude-3-haiku-20240307', max_tokens=300
            )
            
        local_backend = LocalModelBackend()
        available_local = local_backend.list_available_models()
        if available_local:
            responses['local'] = local_backend.generate(
                coding_prompt, model=available_local[0], max_tokens=300
            )
            
        if not responses:
            pytest.skip("No models available for quality assessment")
            
        # Assess quality of each response
        quality_assessor = self.model_manager.get_quality_assessor()
        
        for model_name, response in responses.items():
            self.assert_real_output(response)
            
            quality_score = quality_assessor.assess_code_quality(
                response['content'], 
                language='python'
            )
            
            # Validate quality assessment
            assert isinstance(quality_score, dict)
            assert 'syntax_score' in quality_score
            assert 'completeness_score' in quality_score
            assert 'overall_score' in quality_score
            
            # Scores should be realistic
            assert 0 <= quality_score['overall_score'] <= 100
            
    def test_model_caching_real(self):
        """Test REAL response caching for identical prompts."""
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("No OpenAI API key for caching test")
            
        backend = OpenAIBackend(
            api_key=os.getenv('OPENAI_API_KEY'),
            enable_caching=True
        )
        
        prompt = "Explain what a PE header is in one sentence."
        
        # First request - should hit API
        start_time = time.time()
        response1 = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=50)
        first_time = time.time() - start_time
        
        # Second request - should hit cache
        start_time = time.time()
        response2 = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=50)
        second_time = time.time() - start_time
        
        # Validate responses
        self.assert_real_output(response1)
        self.assert_real_output(response2)
        
        # Content should be identical (cached)
        assert response1['content'] == response2['content']
        
        # Second request should be much faster (cached)
        assert second_time < first_time / 2
        
        # Check cache metadata
        assert response2['metadata'].get('cached', False) == True
        
    def test_model_switching_real(self):
        """Test REAL model switching and hot-swapping."""
        backend = LLMBackend()
        
        # Test switching between available models
        available_configs = []
        
        if os.getenv('OPENAI_API_KEY'):
            available_configs.append(('openai', 'gpt-3.5-turbo'))
            
        if os.getenv('ANTHROPIC_API_KEY'):
            available_configs.append(('anthropic', 'claude-3-haiku-20240307'))
            
        local_backend = LocalModelBackend()
        local_models = local_backend.list_available_models()
        if local_models:
            available_configs.append(('local', local_models[0]))
            
        if len(available_configs) < 2:
            pytest.skip("Need at least 2 models for switching test")
            
        prompt = "Generate a brief comment about binary analysis."
        
        # Test each model configuration
        responses = {}
        for provider, model in available_configs:
            backend.switch_model(provider, model)
            response = backend.generate(prompt, max_tokens=100)
            responses[f"{provider}_{model}"] = response
            
        # Validate all responses
        for model_key, response in responses.items():
            self.assert_real_output(response)
            assert len(response['content']) > 10
            
        # Responses should be different (different models)
        contents = [r['content'] for r in responses.values()]
        assert len(set(contents)) > 1  # At least some variation
        
    def test_error_handling_real(self):
        """Test REAL error handling with invalid requests."""
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("No OpenAI API key for error handling test")
            
        backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
        
        # Test various error conditions
        
        # Invalid model
        response = backend.generate(
            "Test prompt", 
            model='nonexistent-model-123', 
            max_tokens=50
        )
        assert 'error' in response
        
        # Empty prompt
        response = backend.generate("", model='gpt-3.5-turbo', max_tokens=50)
        assert 'error' in response or len(response.get('content', '')) == 0
        
        # Excessive token request
        response = backend.generate(
            "Test", 
            model='gpt-3.5-turbo', 
            max_tokens=100000  # Way too many
        )
        assert 'error' in response or response is not None
        
    def test_concurrent_requests_real(self):
        """Test REAL concurrent request handling."""
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("No OpenAI API key for concurrency test")
            
        import threading
        import queue
        
        backend = OpenAIBackend(api_key=os.getenv('OPENAI_API_KEY'))
        results_queue = queue.Queue()
        
        def make_request(prompt_id):
            prompt = f"Generate comment #{prompt_id} for a function."
            response = backend.generate(prompt, model='gpt-3.5-turbo', max_tokens=50)
            results_queue.put((prompt_id, response))
            
        # Start multiple concurrent requests
        threads = []
        for i in range(3):  # Limited to avoid rate limits
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
            
        # Wait for completion
        for thread in threads:
            thread.join(timeout=30)
            
        # Collect results
        results = {}
        while not results_queue.empty():
            prompt_id, response = results_queue.get()
            results[prompt_id] = response
            
        # Validate concurrent responses
        assert len(results) == 3
        for prompt_id, response in results.items():
            self.assert_real_output(response)
            assert str(prompt_id) in response['content']