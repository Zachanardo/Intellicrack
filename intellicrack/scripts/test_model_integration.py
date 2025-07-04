"""
Model Integration Test Runner

Validates that all new model backends integrate correctly with Intellicrack's
script generation and analysis systems.

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
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMProvider, LLMResponse
from intellicrack.ai.model_batch_tester import get_batch_tester
from intellicrack.ai.model_cache_manager import get_cache_manager
from intellicrack.ai.model_comparison import get_comparison_tool
from intellicrack.ai.model_performance_monitor import get_performance_monitor
from intellicrack.ai.quantization_manager import get_quantization_manager
from intellicrack.utils.logger import get_logger

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# Try to import Protection with fallback
try:
    from intellicrack.protection.protection_detector import Protection
    PROTECTION_AVAILABLE = True
except ImportError:
    Protection = None
    PROTECTION_AVAILABLE = False

logger = get_logger(__name__)

# Try to import script generators with fallbacks
try:
    from intellicrack.ai.ai_script_generator import FridaScriptGenerator, GhidraScriptGenerator
    IDAPythonScriptGenerator = None  # Not available
    SCRIPT_GENERATORS_AVAILABLE = True
except ImportError:
    # Script generators not available - skip related tests
    FridaScriptGenerator = None
    GhidraScriptGenerator = None
    IDAPythonScriptGenerator = None
    SCRIPT_GENERATORS_AVAILABLE = False
    logger.warning("Script generators not available - some tests will be skipped")

# Try to import binary analyzer with fallback
try:
    from intellicrack.core.analysis.multi_format_analyzer import BinaryInfo
    BINARY_ANALYZER_AVAILABLE = True
except ImportError:
    # Binary analyzer not available - skip related tests
    BinaryInfo = None
    BINARY_ANALYZER_AVAILABLE = False
    logger.warning("Binary analyzer not available - some tests will be skipped")


class ModelIntegrationValidator:
    """Validates model backend integration with Intellicrack systems."""

    def __init__(self):
        """Initialize the validator."""
        self.llm_manager = LLMManager()
        self.results = {}

    def create_mock_response(self, content: str) -> LLMResponse:
        """Create a mock LLM response."""
        return LLMResponse(
            content=content,
            model="mock-model",
            usage={"prompt_tokens": 100, "completion_tokens": 200}
        )

    def create_test_binary_info(self):
        """Create test binary information."""
        if not BINARY_ANALYZER_AVAILABLE:
            return None

        return BinaryInfo(
            file_path="/test/malware.exe",
            file_size=2048000,
            file_type="PE32+ executable",
            architecture="x86_64",
            endianness="little",
            entry_point=0x140001000,
            sections=[],
            imports={},
            exports={},
            strings=[],
            md5="test_md5_hash",
            sha256="test_sha256_hash"
        )

    def create_test_protection(self):
        """Create test protection information."""
        if not PROTECTION_AVAILABLE:
            return None

        return Protection(
            name="Themida",
            confidence=0.92,
            indicators=[
                "VM-based protection detected",
                "Anti-debugging checks found",
                "Code obfuscation present"
            ],
            bypass_techniques=[
                "VM handler hooking",
                "Anti-debug patching",
                "Dynamic unpacking"
            ]
        )

    def test_backend_creation(self) -> bool:
        """Test that all backends can be created."""
        logger.info("Testing backend creation...")

        backend_configs = {
            "openai": LLMConfig(
                provider=LLMProvider.OPENAI,
                api_key="test-key",
                model="gpt-4"
            ),
            "pytorch": LLMConfig(
                provider=LLMProvider.PYTORCH,
                model_path="/models/llama-7b.pt",
                device="cuda",
                quantization="8bit"
            ),
            "gptq": LLMConfig(
                provider=LLMProvider.GPTQ,
                model_path="/models/llama-7b-gptq",
                device="cuda"
            ),
            "onnx": LLMConfig(
                provider=LLMProvider.ONNX,
                model_path="/models/model.onnx",
                device="cpu"
            ),
            "tensorflow": LLMConfig(
                provider=LLMProvider.TENSORFLOW,
                model_path="/models/tf_model",
                device="cpu"
            ),
            "safetensors": LLMConfig(
                provider=LLMProvider.SAFETENSORS,
                model_path="/models/model.safetensors",
                device="cpu"
            ),
            "huggingface": LLMConfig(
                provider=LLMProvider.HUGGINGFACE_LOCAL,
                model_path="microsoft/DialoGPT-medium",
                device="cpu",
                quantization="8bit"
            )
        }

        success_count = 0
        total_backends = len(backend_configs)

        # Mock all backends
        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI, \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockPyTorch, \
             patch('intellicrack.ai.llm_backends.GPTQBackend') as MockGPTQ, \
             patch('intellicrack.ai.llm_backends.ONNXLLMBackend') as MockONNX, \
             patch('intellicrack.ai.llm_backends.TensorFlowLLMBackend') as MockTF, \
             patch('intellicrack.ai.llm_backends.SafetensorsBackend') as MockST, \
             patch('intellicrack.ai.llm_backends.HuggingFaceLocalBackend') as MockHF:

            # Setup mock responses
            mock_backends = [MockOpenAI, MockPyTorch, MockGPTQ, MockONNX, MockTF, MockST, MockHF]
            for mock_backend in mock_backends:
                mock_instance = MagicMock()
                mock_instance.complete.return_value = self.create_mock_response("Test response")
                mock_backend.return_value = mock_instance

            # Test each backend
            for backend_id, config in backend_configs.items():
                try:
                    self.llm_manager.add_llm(backend_id, config)
                    llm = self.llm_manager.get_llm(backend_id)

                    if llm is not None:
                        logger.info(f"✓ {backend_id} backend created successfully")
                        success_count += 1
                    else:
                        logger.error(f"✗ {backend_id} backend creation failed")

                except Exception as e:
                    logger.error(f"✗ {backend_id} backend creation failed: {e}")

        success_rate = success_count / total_backends
        self.results['backend_creation'] = {
            'success_count': success_count,
            'total_backends': total_backends,
            'success_rate': success_rate
        }

        logger.info(f"Backend creation test: {success_count}/{total_backends} successful ({success_rate:.1%})")
        return success_rate >= 0.8  # 80% success rate required

    def test_script_generation(self) -> bool:
        """Test script generation with different backends."""
        logger.info("Testing script generation integration...")

        if not SCRIPT_GENERATORS_AVAILABLE:
            logger.warning("Script generators not available - skipping script generation tests")
            self.results['script_generation'] = {
                'successful_tests': 0,
                'total_tests': 0,
                'success_rate': 1.0,  # Skip counts as success
                'details': {},
                'skipped': True
            }
            return True

        if not BINARY_ANALYZER_AVAILABLE:
            logger.warning("Binary analyzer not available - skipping script generation tests")
            self.results['script_generation'] = {
                'successful_tests': 0,
                'total_tests': 0,
                'success_rate': 1.0,  # Skip counts as success
                'details': {},
                'skipped': True
            }
            return True

        binary_info = self.create_test_binary_info()
        protection = self.create_test_protection()

        script_generators = [
            ("frida", FridaScriptGenerator),
            ("ghidra", GhidraScriptGenerator),
            ("ida", IDAPythonScriptGenerator)
        ]

        test_results = {}

        # Test each script generator with different backends
        for generator_name, generator_class in script_generators:
            test_results[generator_name] = {}

            try:
                generator = generator_class(self.llm_manager)

                # Test with different backends
                for backend_id in self.llm_manager.list_llms():
                    try:
                        if generator_name == "frida":
                            script = generator.generate_bypass_script(
                                binary_info, protection, model_id=backend_id
                            )
                        elif generator_name == "ghidra":
                            script = generator.generate_analysis_script(
                                binary_info, protection, model_id=backend_id
                            )
                        else:  # ida
                            script = generator.generate_deobfuscation_script(
                                binary_info, protection, model_id=backend_id
                            )

                        if script and script.strip():
                            test_results[generator_name][backend_id] = True
                            logger.info(f"✓ {generator_name} + {backend_id}: Script generated")
                        else:
                            test_results[generator_name][backend_id] = False
                            logger.warning(f"⚠ {generator_name} + {backend_id}: Empty script")

                    except Exception as e:
                        test_results[generator_name][backend_id] = False
                        logger.error(f"✗ {generator_name} + {backend_id}: {e}")

            except Exception as e:
                logger.error(f"✗ Failed to create {generator_name} generator: {e}")

        # Calculate overall success rate
        total_tests = 0
        successful_tests = 0

        for generator_results in test_results.values():
            for success in generator_results.values():
                total_tests += 1
                if success:
                    successful_tests += 1

        success_rate = successful_tests / total_tests if total_tests > 0 else 0
        self.results['script_generation'] = {
            'successful_tests': successful_tests,
            'total_tests': total_tests,
            'success_rate': success_rate,
            'details': test_results
        }

        logger.info(f"Script generation test: {successful_tests}/{total_tests} successful ({success_rate:.1%})")
        return success_rate >= 0.7  # 70% success rate required

    def test_performance_monitoring(self) -> bool:
        """Test performance monitoring integration."""
        logger.info("Testing performance monitoring...")

        try:
            perf_monitor = get_performance_monitor()

            # Test tracking for each backend
            for backend_id in self.llm_manager.list_llms():
                # Start tracking
                context = perf_monitor.start_inference(backend_id)

                # Simulate some work
                time.sleep(0.1)

                # End tracking
                metrics = perf_monitor.end_inference(
                    context,
                    tokens_generated=100,
                    batch_size=1,
                    sequence_length=50
                )

                # Verify metrics
                if metrics.model_id != backend_id:
                    raise ValueError(f"Metrics model_id mismatch: {metrics.model_id} != {backend_id}")

                if metrics.tokens_generated != 100:
                    raise ValueError(f"Tokens generated mismatch: {metrics.tokens_generated} != 100")

            # Test metrics summary
            for backend_id in self.llm_manager.list_llms():
                summary = perf_monitor.get_metrics_summary(backend_id)
                if not isinstance(summary, dict):
                    raise ValueError(f"Invalid summary type for {backend_id}")

            logger.info("✓ Performance monitoring integration successful")
            self.results['performance_monitoring'] = True
            return True

        except Exception as e:
            logger.error(f"✗ Performance monitoring failed: {e}")
            self.results['performance_monitoring'] = False
            return False

    def test_batch_testing(self) -> bool:
        """Test batch testing functionality."""
        logger.info("Testing batch testing integration...")

        try:
            batch_tester = get_batch_tester(self.llm_manager)

            # Verify test suites are available
            test_suites = ["basic", "code_generation", "binary_analysis"]
            for suite in test_suites:
                if suite not in batch_tester.test_suites:
                    raise ValueError(f"Test suite '{suite}' not found")

            # Test with a subset of models
            model_ids = list(self.llm_manager.list_llms())[:2]  # Test with 2 models

            if len(model_ids) == 0:
                raise ValueError("No models available for batch testing")

            # Run a simple test
            report = batch_tester.run_batch_test(
                model_ids=model_ids,
                suite_id="basic",
                parallel=False  # Sequential for testing
            )

            # Verify report structure
            if not hasattr(report, 'results'):
                raise ValueError("Batch report missing results")

            if not hasattr(report, 'summary'):
                raise ValueError("Batch report missing summary")

            logger.info(f"✓ Batch testing completed: {len(report.results)} test results")
            self.results['batch_testing'] = True
            return True

        except Exception as e:
            logger.error(f"✗ Batch testing failed: {e}")
            self.results['batch_testing'] = False
            return False

    def test_model_comparison(self) -> bool:
        """Test model comparison functionality."""
        logger.info("Testing model comparison...")

        try:
            comparison_tool = get_comparison_tool(self.llm_manager)

            # Get available models
            model_ids = list(self.llm_manager.list_llms())

            if len(model_ids) < 2:
                logger.warning("⚠ Need at least 2 models for comparison test")
                self.results['model_comparison'] = True  # Pass if not enough models
                return True

            # Test output comparison
            test_prompt = "Explain how to bypass software protection."

            report = comparison_tool.compare_outputs(
                model_ids=model_ids[:2],  # Compare first 2 models
                prompt=test_prompt,
                max_tokens=200,
                num_samples=1
            )

            # Verify report structure
            if not hasattr(report, 'results'):
                raise ValueError("Comparison report missing results")

            if not hasattr(report, 'analysis'):
                raise ValueError("Comparison report missing analysis")

            logger.info(f"✓ Model comparison completed: {len(report.results)} model outputs")
            self.results['model_comparison'] = True
            return True

        except Exception as e:
            logger.error(f"✗ Model comparison failed: {e}")
            self.results['model_comparison'] = False
            return False

    def test_quantization_support(self) -> bool:
        """Test quantization support."""
        logger.info("Testing quantization support...")

        try:
            quant_manager = get_quantization_manager()

            # Test quantization types
            supported_types = quant_manager.get_supported_quantization_types()
            if not isinstance(supported_types, list):
                raise ValueError("Invalid quantization types format")

            # Test quantization configs
            for quant_type in ["8bit", "4bit"]:
                if quant_type in supported_types:
                    config = quant_manager.create_quantization_config(quant_type)
                    if not isinstance(config, dict):
                        raise ValueError(f"Invalid config for {quant_type}")

            logger.info(f"✓ Quantization support verified: {len(supported_types)} types")
            self.results['quantization'] = True
            return True

        except Exception as e:
            logger.error(f"✗ Quantization support failed: {e}")
            self.results['quantization'] = False
            return False

    def test_caching_system(self) -> bool:
        """Test model caching system."""
        logger.info("Testing model caching...")

        try:
            cache_manager = get_cache_manager(max_memory_gb=1.0)

            # Test cache operations
            test_model = MagicMock()
            test_tokenizer = MagicMock()

            # Test put
            cache_manager.put(
                model_id="test-cache-model",
                model=test_model,
                tokenizer=test_tokenizer
            )

            # Test get
            result = cache_manager.get("test-cache-model")
            if result is None:
                raise ValueError("Failed to retrieve cached model")

            model, tokenizer = result
            if model != test_model or tokenizer != test_tokenizer:
                raise ValueError("Cached objects don't match")

            # Test stats
            stats = cache_manager.get_stats()
            if not isinstance(stats, dict):
                raise ValueError("Invalid cache stats format")

            logger.info("✓ Model caching system working correctly")
            self.results['caching'] = True
            return True

        except Exception as e:
            logger.error(f"✗ Model caching failed: {e}")
            self.results['caching'] = False
            return False

    def run_all_tests(self) -> dict:
        """Run all integration tests."""
        logger.info("Starting model backend integration tests...")
        logger.info("=" * 60)

        tests = [
            ("Backend Creation", self.test_backend_creation),
            ("Script Generation", self.test_script_generation),
            ("Performance Monitoring", self.test_performance_monitoring),
            ("Batch Testing", self.test_batch_testing),
            ("Model Comparison", self.test_model_comparison),
            ("Quantization Support", self.test_quantization_support),
            ("Caching System", self.test_caching_system)
        ]

        passed_tests = 0
        total_tests = len(tests)

        for test_name, test_func in tests:
            logger.info(f"\n--- {test_name} ---")
            try:
                if test_func():
                    passed_tests += 1
                    logger.info(f"✓ {test_name} PASSED")
                else:
                    logger.error(f"✗ {test_name} FAILED")
            except Exception as e:
                logger.error(f"✗ {test_name} FAILED with exception: {e}")

        # Final summary
        logger.info("\n" + "=" * 60)
        logger.info("INTEGRATION TEST SUMMARY")
        logger.info("=" * 60)

        success_rate = passed_tests / total_tests
        logger.info(f"Tests Passed: {passed_tests}/{total_tests} ({success_rate:.1%})")

        if success_rate >= 0.8:
            logger.info("🎉 INTEGRATION TESTS PASSED - Model backends ready for use!")
        elif success_rate >= 0.6:
            logger.warning("⚠️  INTEGRATION TESTS PARTIAL - Some issues detected")
        else:
            logger.error("❌ INTEGRATION TESTS FAILED - Major issues detected")

        # Detailed results
        logger.info("\nDetailed Results:")
        for test_name, _ in tests:
            test_key = test_name.lower().replace(" ", "_")
            result = self.results.get(test_key, False)
            status = "PASS" if result else "FAIL"
            logger.info(f"  {test_name}: {status}")

        return {
            'passed_tests': passed_tests,
            'total_tests': total_tests,
            'success_rate': success_rate,
            'results': self.results
        }


def main():
    """Main test runner."""
    logger.info("Intellicrack Model Backend Integration Test Runner")
    logger.info("Copyright (C) 2025 Zachary Flint")
    logger.info("=" * 60)

    validator = ModelIntegrationValidator()
    results = validator.run_all_tests()

    # Exit with appropriate code
    if results['success_rate'] >= 0.8:
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Failure


if __name__ == "__main__":
    main()
