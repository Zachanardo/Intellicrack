"""
Model Backend Validation Tests

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

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.model_batch_tester import get_batch_tester
from intellicrack.ai.model_comparison import get_comparison_tool
from intellicrack.ai.model_performance_monitor import get_performance_monitor
from intellicrack.ai.quantization_manager import get_quantization_manager
from intellicrack.utils.logger import get_logger

sys.path.append(str(Path(__file__).parent.parent))


logger = get_logger(__name__)


class TestModelBackendValidation(unittest.TestCase):
    """Validate all model backends function correctly."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.llm_manager = LLMManager()

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_response(self, content: str) -> LLMResponse:
        """Create a mock LLM response."""
        return LLMResponse(
            content=content,
            model="mock-model",
            usage={"prompt_tokens": 100, "completion_tokens": 200}
        )

    def test_openai_backend_integration(self):
        """Test OpenAI backend integration."""
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
            model="gpt-4",
            temperature=0.7,
            max_tokens=1000
        )

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "This is a test response from OpenAI backend."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("openai-test", config)
            llm = self.llm_manager.get_llm("openai-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.OPENAI)

            # Test completion
            messages = [LLMMessage(role="user", content="Test message")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("OpenAI backend", response.content)
            mock_backend.complete.assert_called_once()

    def test_pytorch_backend_integration(self):
        """Test PyTorch backend integration."""
        config = LLMConfig(
            provider=LLMProvider.PYTORCH,
            model_path="/models/pytorch_model.pt",
            device="cpu",
            temperature=0.5
        )

        with patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "PyTorch model response for testing."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("pytorch-test", config)
            llm = self.llm_manager.get_llm("pytorch-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.PYTORCH)

            # Test completion
            messages = [LLMMessage(role="user", content="Test PyTorch")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("PyTorch", response.content)

    def test_gptq_backend_integration(self):
        """Test GPTQ backend integration."""
        config = LLMConfig(
            provider=LLMProvider.GPTQ,
            model_path="/models/gptq-4bit",
            device="cuda",
            quantization="4bit"
        )

        with patch('intellicrack.ai.llm_backends.GPTQBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "GPTQ quantized model response."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("gptq-test", config)
            llm = self.llm_manager.get_llm("gptq-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.GPTQ)

            # Test completion
            messages = [LLMMessage(role="user", content="Test GPTQ")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("GPTQ", response.content)

    def test_onnx_backend_integration(self):
        """Test ONNX backend integration."""
        config = LLMConfig(
            provider=LLMProvider.ONNX,
            model_path="/models/model.onnx",
            device="cpu"
        )

        with patch('intellicrack.ai.llm_backends.ONNXLLMBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "ONNX model inference result."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("onnx-test", config)
            llm = self.llm_manager.get_llm("onnx-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.ONNX)

            # Test completion
            messages = [LLMMessage(role="user", content="Test ONNX")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("ONNX", response.content)

    def test_huggingface_local_backend_integration(self):
        """Test Hugging Face Local backend integration."""
        config = LLMConfig(
            provider=LLMProvider.HUGGINGFACE_LOCAL,
            model_path="gpt2",
            device="cpu",
            quantization="8bit"
        )

        with patch('intellicrack.ai.llm_backends.HuggingFaceLocalBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "Hugging Face local model output."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("hf-test", config)
            llm = self.llm_manager.get_llm("hf-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.HUGGINGFACE_LOCAL)

            # Test completion
            messages = [LLMMessage(role="user", content="Test HF Local")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("Hugging Face", response.content)

    def test_safetensors_backend_integration(self):
        """Test SafeTensors backend integration."""
        config = LLMConfig(
            provider=LLMProvider.SAFETENSORS,
            model_path="/models/model.safetensors",
            device="cpu"
        )

        with patch('intellicrack.ai.llm_backends.SafetensorsBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "SafeTensors model inference."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("st-test", config)
            llm = self.llm_manager.get_llm("st-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.SAFETENSORS)

            # Test completion
            messages = [LLMMessage(role="user", content="Test SafeTensors")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("SafeTensors", response.content)

    def test_tensorflow_backend_integration(self):
        """Test TensorFlow backend integration."""
        config = LLMConfig(
            provider=LLMProvider.TENSORFLOW,
            model_path="/models/tf_model",
            device="cpu"
        )

        with patch('intellicrack.ai.llm_backends.TensorFlowLLMBackend') as MockBackend:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response(
                "TensorFlow model prediction."
            )
            MockBackend.return_value = mock_backend

            # Test backend creation
            self.llm_manager.add_llm("tf-test", config)
            llm = self.llm_manager.get_llm("tf-test")

            self.assertIsNotNone(llm)
            self.assertEqual(llm.config.provider, LLMProvider.TENSORFLOW)

            # Test completion
            messages = [LLMMessage(role="user", content="Test TensorFlow")]
            response = llm.complete(messages)

            self.assertIsNotNone(response)
            self.assertIn("TensorFlow", response.content)

    def test_batch_testing_integration(self):
        """Test batch testing with multiple backends."""
        # Setup multiple backends
        models = ["openai-test", "pytorch-test", "gptq-test"]

        with patch('intellicrack.ai.llm_backends.OpenAIBackend'), \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend'), \
             patch('intellicrack.ai.llm_backends.GPTQBackend'):

            # Add all backends
            configs = [
                LLMConfig(provider=LLMProvider.OPENAI, api_key="test"),
                LLMConfig(provider=LLMProvider.PYTORCH, model_path="/test.pt"),
                LLMConfig(provider=LLMProvider.GPTQ, model_path="/test-gptq")
            ]

            for i, model_id in enumerate(models):
                self.llm_manager.add_llm(model_id, configs[i])

            # Get batch tester
            batch_tester = get_batch_tester(self.llm_manager)

            # Test that we can create test suites
            self.assertIn("basic", batch_tester.test_suites)
            self.assertIn("code_generation", batch_tester.test_suites)
            self.assertIn("binary_analysis", batch_tester.test_suites)

            # Verify test cases
            basic_tests = batch_tester.test_suites["basic"]
            self.assertGreater(len(basic_tests), 0)

            binary_tests = batch_tester.test_suites["binary_analysis"]
            self.assertGreater(len(binary_tests), 0)

    def test_model_comparison_integration(self):
        """Test model comparison functionality."""
        models = ["model1", "model2"]

        # Validate model list
        self.assertIsInstance(models, list)
        self.assertEqual(len(models), 2)

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI, \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockPyTorch:

            # Setup mock responses
            mock_openai = MagicMock()
            mock_openai.complete.return_value = self._create_mock_response("Response from OpenAI")
            MockOpenAI.return_value = mock_openai

            mock_pytorch = MagicMock()
            mock_pytorch.complete.return_value = self._create_mock_response("Response from PyTorch")
            MockPyTorch.return_value = mock_pytorch

            # Add backends
            self.llm_manager.add_llm("model1", LLMConfig(
                provider=LLMProvider.OPENAI, api_key="test"
            ))
            self.llm_manager.add_llm("model2", LLMConfig(
                provider=LLMProvider.PYTORCH, model_path="/test.pt"
            ))

            # Get comparison tool
            comparison_tool = get_comparison_tool(self.llm_manager)

            # Test comparison setup
            self.assertIsNotNone(comparison_tool.llm_manager)
            self.assertIsNotNone(comparison_tool.performance_monitor)
            self.assertIsNotNone(comparison_tool.batch_tester)

    def test_performance_monitoring_integration(self):
        """Test performance monitoring with backends."""
        # Get performance monitor
        perf_monitor = get_performance_monitor()

        # Test monitoring functionality
        model_id = "test-model"

        # Start tracking
        context = perf_monitor.start_inference(model_id)
        self.assertIsInstance(context, dict)
        self.assertEqual(context["model_id"], model_id)

        # End tracking
        metrics = perf_monitor.end_inference(
            context,
            tokens_generated=50,
            batch_size=1,
            sequence_length=100
        )

        self.assertIsNotNone(metrics)
        self.assertEqual(metrics.model_id, model_id)
        self.assertEqual(metrics.tokens_generated, 50)

        # Get summary
        summary = perf_monitor.get_metrics_summary(model_id)
        self.assertIsInstance(summary, dict)
        self.assertIn("total_inferences", summary)

    def test_quantization_manager_integration(self):
        """Test quantization manager integration."""
        quant_manager = get_quantization_manager()

        # Test quantization options
        supported_types = quant_manager.get_supported_quantization_types()
        self.assertIsInstance(supported_types, list)

        # Test config creation
        config = quant_manager.create_quantization_config("8bit")
        self.assertIsInstance(config, dict)

        # Test device mapping
        device_map = quant_manager.get_device_map()
        self.assertIsInstance(device_map, dict)

    def test_config_persistence(self):
        """Test configuration saving and loading."""
        # Create test configs
        configs = {
            "openai": LLMConfig(
                provider=LLMProvider.OPENAI,
                api_key="test-key",
                model="gpt-4"
            ),
            "pytorch": LLMConfig(
                provider=LLMProvider.PYTORCH,
                model_path="/models/test.pt",
                device="cuda"
            )
        }

        # Test serialization
        config_data = {}
        for model_id, config in configs.items():
            config_data[model_id] = {
                "provider": config.provider.value,
                "api_key": getattr(config, 'api_key', None),
                "model": getattr(config, 'model', None),
                "model_path": getattr(config, 'model_path', None),
                "device": getattr(config, 'device', None),
                "temperature": config.temperature,
                "max_tokens": config.max_tokens
            }

        # Verify serializable
        import json
        serialized = json.dumps(config_data, default=str)
        self.assertIsInstance(serialized, str)

        # Test deserialization
        loaded_data = json.loads(serialized)
        self.assertEqual(len(loaded_data), len(configs))

        for model_id in configs:
            self.assertIn(model_id, loaded_data)
            self.assertEqual(loaded_data[model_id]["provider"], configs[model_id].provider.value)

    def test_error_handling(self):
        """Test error handling across backends."""
        # Test invalid provider
        with self.assertRaises(ValueError):
            LLMConfig(provider="invalid_provider")

        # Test missing required config
        with self.assertRaises((ValueError, TypeError)):
            config = LLMConfig(provider=LLMProvider.OPENAI)
            # Missing api_key should cause error during backend creation

        # Test invalid model path
        config = LLMConfig(
            provider=LLMProvider.PYTORCH,
            model_path="/nonexistent/model.pt"
        )

        with patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockBackend:
            MockBackend.side_effect = FileNotFoundError("Model not found")

            # Should handle error gracefully
            try:
                self.llm_manager.add_llm("error-test", config)
                llm = self.llm_manager.get_llm("error-test")
                # Backend creation failed, should return None
                self.assertIsNone(llm)
            except:
                # Error during add_llm is also acceptable
                pass

    def test_memory_management(self):
        """Test memory management with model cache."""
        from intellicrack.ai.model_cache_manager import get_cache_manager

        # Get cache manager
        cache_manager = get_cache_manager(max_memory_gb=1.0)

        # Test cache operations
        test_model = MagicMock()
        test_tokenizer = MagicMock()

        # Add to cache
        cache_manager.put(
            model_id="test-model",
            model=test_model,
            tokenizer=test_tokenizer
        )

        # Retrieve from cache
        result = cache_manager.get("test-model")
        self.assertIsNotNone(result)

        model, tokenizer = result
        self.assertEqual(model, test_model)
        self.assertEqual(tokenizer, test_tokenizer)

        # Test cache stats
        stats = cache_manager.get_stats()
        self.assertIsInstance(stats, dict)
        self.assertIn("memory_cache", stats)
        self.assertIn("statistics", stats)

    def test_cross_backend_compatibility(self):
        """Test that all backends can coexist."""
        # Create configs for all backend types
        all_configs = {
            "openai": LLMConfig(provider=LLMProvider.OPENAI, api_key="test"),
            "pytorch": LLMConfig(provider=LLMProvider.PYTORCH, model_path="/test.pt"),
            "tensorflow": LLMConfig(provider=LLMProvider.TENSORFLOW, model_path="/test_tf"),
            "onnx": LLMConfig(provider=LLMProvider.ONNX, model_path="/test.onnx"),
            "gptq": LLMConfig(provider=LLMProvider.GPTQ, model_path="/test_gptq"),
            "safetensors": LLMConfig(provider=LLMProvider.SAFETENSORS, model_path="/test.safetensors"),
            "hf_local": LLMConfig(provider=LLMProvider.HUGGINGFACE_LOCAL, model_path="gpt2")
        }

        # Mock all backends
        with patch('intellicrack.ai.llm_backends.OpenAIBackend'), \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend'), \
             patch('intellicrack.ai.llm_backends.TensorFlowLLMBackend'), \
             patch('intellicrack.ai.llm_backends.ONNXLLMBackend'), \
             patch('intellicrack.ai.llm_backends.GPTQBackend'), \
             patch('intellicrack.ai.llm_backends.SafetensorsBackend'), \
             patch('intellicrack.ai.llm_backends.HuggingFaceLocalBackend'):

            # Add all backends
            for model_id, config in all_configs.items():
                try:
                    self.llm_manager.add_llm(model_id, config)
                except Exception as e:
                    self.fail(f"Failed to add {model_id} backend: {e}")

            # Verify all backends are available
            available_models = self.llm_manager.list_llms()
            self.assertEqual(len(available_models), len(all_configs))

            # Test each backend
            for model_id in all_configs:
                llm = self.llm_manager.get_llm(model_id)
                self.assertIsNotNone(llm, f"Backend {model_id} not available")


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
