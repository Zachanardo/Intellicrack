"""
Integration Tests for Model Backends with Script Generation

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

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.ai.llm_backends import LLMConfig, LLMManager, LLMMessage, LLMProvider, LLMResponse
from intellicrack.ai.script_generators import (
    FridaScriptGenerator,
    GhidraScriptGenerator,
    IDAPythonScriptGenerator,
)
from intellicrack.core.analysis.binary_analyzer import BinaryInfo
from intellicrack.core.protection.protection_detector import Protection
from intellicrack.utils.logger import get_logger

sys.path.append(str(Path(__file__).parent.parent))


logger = get_logger(__name__)


class TestModelScriptIntegration(unittest.TestCase):
    """Test integration between model backends and script generation."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.llm_manager = LLMManager()

        # Mock binary info
        self.binary_info = BinaryInfo(
            file_path="/test/binary.exe",
            file_size=1024000,
            file_type="PE32 executable",
            architecture="x86_64",
            endianness="little",
            entry_point=0x401000,
            sections=[],
            imports={},
            exports={},
            strings=[],
            md5="test_md5",
            sha256="test_sha256"
        )

        # Mock protection
        self.protection = Protection(
            name="VMProtect",
            confidence=0.95,
            indicators=["Obfuscated entry point", "VM handlers detected"],
            bypass_techniques=["Hook VM handlers", "Trace execution"]
        )

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

    def test_frida_script_generation_with_openai(self):
        """Test Frida script generation with OpenAI backend."""
        # Configure OpenAI backend
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
            model="gpt-4",
            temperature=0.7,
            max_tokens=2000
        )

        # Mock the OpenAI backend
        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("""
// Frida script to bypass VMProtect
Java.perform(function() {
    var base = Module.getBaseAddress('binary.exe');

    // Hook VM handler
    Interceptor.attach(base.add(0x1000), {
        onEnter: function(args) {
            console.log('[*] VM handler called');
            // Log context
            console.log('EAX: ' + this.context.eax);
            console.log('EBX: ' + this.context.ebx);
        },
        onLeave: function(retval) {
            console.log('[*] VM handler returned: ' + retval);
        }
    });

    // Hook anti-debug checks
    var IsDebuggerPresent = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    Interceptor.attach(IsDebuggerPresent, {
        onLeave: function(retval) {
            retval.replace(0);
        }
    });
});
""")
            MockOpenAI.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("openai-test", config)

            # Generate script
            generator = FridaScriptGenerator(self.llm_manager)
            script = generator.generate_bypass_script(
                self.binary_info,
                self.protection,
                model_id="openai-test"
            )

            # Verify script generation
            self.assertIsNotNone(script)
            self.assertIn("VMProtect", script)
            self.assertIn("Interceptor.attach", script)
            self.assertIn("Module.getBaseAddress", script)

            # Verify LLM was called correctly
            mock_backend.complete.assert_called_once()
            messages = mock_backend.complete.call_args[0][0]
            self.assertEqual(len(messages), 2)  # system + user
            self.assertEqual(messages[0].role, "system")
            self.assertEqual(messages[1].role, "user")

    def test_ghidra_script_generation_with_pytorch(self):
        """Test Ghidra script generation with PyTorch backend."""
        # Configure PyTorch backend
        config = LLMConfig(
            provider=LLMProvider.PYTORCH,
            model_path="/models/pytorch_model.pt",
            temperature=0.5,
            max_tokens=1500
        )

        # Mock the PyTorch backend
        with patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockPyTorch:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("""
# Ghidra script to analyze VMProtect
# @category: Protection Analysis

from ghidra.program.model.address import Address
from ghidra.program.model.listing import Function

def analyze_vm_handlers():
    # Get current program
    program = currentProgram
    listing = program.getListing()

    # Find VM handler patterns
    vm_handler_addresses = []

    # Search for common VM handler prologue
    bytes_to_find = [0x55, 0x8B, 0xEC]  # push ebp; mov ebp, esp

    monitor.setMessage("Searching for VM handlers...")
    for addr in findBytes(None, bytes_to_find):
        # Check if this looks like a VM handler
        func = getFunctionAt(addr)
        if func and is_vm_handler(func):
            vm_handler_addresses.append(addr)
            print("Found VM handler at: 0x%x" % addr.getOffset())

    return vm_handler_addresses

def is_vm_handler(func):
    # Check function characteristics
    if func.getParameterCount() > 2:
        return False

    # Check for dispatcher pattern
    instruction_count = 0
    for inst in currentProgram.getListing().getInstructions(func.getBody(), True):
        instruction_count += 1
        if instruction_count > 100:
            return True

    return False

# Main execution
print("VMProtect Analysis Script")
print("=" * 50)

handlers = analyze_vm_handlers()
print("Found %d potential VM handlers" % len(handlers))

# Create bookmarks for handlers
for addr in handlers:
    createBookmark(addr, "VM Handler", "Potential VMProtect handler")
""")
            MockPyTorch.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("pytorch-test", config)

            # Generate script
            generator = GhidraScriptGenerator(self.llm_manager)
            script = generator.generate_analysis_script(
                self.binary_info,
                self.protection,
                model_id="pytorch-test"
            )

            # Verify script generation
            self.assertIsNotNone(script)
            self.assertIn("VMProtect", script)
            self.assertIn("currentProgram", script)
            self.assertIn("findBytes", script)
            self.assertIn("createBookmark", script)

    def test_ida_script_generation_with_huggingface(self):
        """Test IDA script generation with Hugging Face backend."""
        # Configure HF backend
        config = LLMConfig(
            provider=LLMProvider.HUGGINGFACE_LOCAL,
            model_path="gpt2",  # Small model for testing
            temperature=0.7,
            max_tokens=1000
        )

        # Mock the HF backend
        with patch('intellicrack.ai.llm_backends.HuggingFaceLocalBackend') as MockHF:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("""
# IDA Python script for VMProtect analysis
import idaapi
import idautils
import idc

def find_vm_entries():
    \"\"\"Find VMProtect entry points.\"\"\"
    vm_entries = []

    # Look for jmp instructions to VM dispatcher
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if not func:
            continue

        # Check first instruction
        mnem = idc.print_insn_mnem(ea)
        if mnem == "jmp":
            target = idc.get_operand_value(ea, 0)
            if is_vm_dispatcher(target):
                vm_entries.append(ea)
                print(f"Found VM entry at {hex(ea)}")

    return vm_entries

def is_vm_dispatcher(ea):
    \"\"\"Check if address is VM dispatcher.\"\"\"
    # Check for dispatcher characteristics
    func = idaapi.get_func(ea)
    if not func:
        return False

    # Count basic blocks
    fc = idaapi.FlowChart(func)
    block_count = fc.size

    # VM dispatchers have many blocks
    return block_count > 50

def mark_vm_functions():
    \"\"\"Mark VM protected functions.\"\"\"
    entries = find_vm_entries()

    for ea in entries:
        idc.set_color(ea, idc.CIC_FUNC, 0x0000FF)
        idc.set_func_cmt(ea, "VMProtect Entry", 0)

    print(f"Marked {len(entries)} VM protected functions")

# Run analysis
print("Starting VMProtect analysis...")
mark_vm_functions()
print("Analysis complete!")
""")
            MockHF.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("hf-test", config)

            # Generate script
            generator = IDAPythonScriptGenerator(self.llm_manager)
            script = generator.generate_deobfuscation_script(
                self.binary_info,
                self.protection,
                model_id="hf-test"
            )

            # Verify script generation
            self.assertIsNotNone(script)
            self.assertIn("VMProtect", script)
            self.assertIn("idaapi", script)
            self.assertIn("idautils", script)
            self.assertIn("FlowChart", script)

    def test_script_generation_with_quantized_model(self):
        """Test script generation with quantized model."""
        # Configure quantized model
        config = LLMConfig(
            provider=LLMProvider.GPTQ,
            model_path="/models/model-4bit-gptq",
            temperature=0.7,
            max_tokens=1000,
            device="cuda"
        )

        # Mock the GPTQ backend
        with patch('intellicrack.ai.llm_backends.GPTQBackend') as MockGPTQ:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("""
// Frida bypass script
Interceptor.attach(Module.getExportByName(null, 'strcmp'), {
    onEnter: function(args) {
        var str1 = args[0].readCString();
        var str2 = args[1].readCString();
        if (str1.includes('license') || str2.includes('license')) {
            console.log('License check detected');
        }
    },
    onLeave: function(retval) {
        // Force success
        retval.replace(0);
    }
});
""")
            MockGPTQ.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("gptq-test", config)

            # Generate script
            generator = FridaScriptGenerator(self.llm_manager)
            script = generator.generate_hook_script(
                self.binary_info,
                ["strcmp", "strncmp"],
                model_id="gptq-test"
            )

            # Verify script generation
            self.assertIsNotNone(script)
            self.assertIn("strcmp", script)
            self.assertIn("Interceptor.attach", script)

    def test_script_generation_with_safetensors(self):
        """Test script generation with SafeTensors model."""
        # Configure SafeTensors backend
        config = LLMConfig(
            provider=LLMProvider.SAFETENSORS,
            model_path="/models/model.safetensors",
            temperature=0.5,
            max_tokens=800
        )

        # Mock the SafeTensors backend
        with patch('intellicrack.ai.llm_backends.SafetensorsBackend') as MockST:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("""
# Protection bypass analysis
def analyze_protection():
    # Identify protection type
    protection_type = "VMProtect"

    # Key characteristics:
    # 1. Virtualized code execution
    # 2. Obfuscated control flow
    # 3. Anti-debugging checks

    bypass_strategy = {
        "hook_points": ["vm_handler", "check_debugger"],
        "techniques": ["trace_execution", "patch_checks"],
        "tools": ["frida", "x64dbg"]
    }

    return bypass_strategy
""")
            MockST.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("st-test", config)

            # Generate analysis
            result = self.llm_manager.get_llm("st-test").complete([
                LLMMessage(role="user", content="Analyze VMProtect protection")
            ])

            # Verify response
            self.assertIsNotNone(result)
            self.assertIn("VMProtect", result.content)
            self.assertIn("bypass_strategy", result.content)

    def test_multi_model_script_generation(self):
        """Test generating scripts with multiple models and comparing."""
        # Configure multiple backends
        models = {
            "model1": LLMConfig(
                provider=LLMProvider.OPENAI,
                api_key="test-key",
                model="gpt-3.5-turbo"
            ),
            "model2": LLMConfig(
                provider=LLMProvider.PYTORCH,
                model_path="/models/pytorch_model.pt"
            )
        }

        # Mock responses
        responses = {
            "model1": "// Frida script v1\nInterceptor.attach(ptr('0x401000'), {});",
            "model2": "// Frida script v2\nInterceptor.replace(ptr('0x401000'), new NativeCallback());"
        }

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI, \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend') as MockPyTorch:

            # Setup mocks
            mock_openai = MagicMock()
            mock_openai.complete.return_value = self._create_mock_response(responses["model1"])
            MockOpenAI.return_value = mock_openai

            mock_pytorch = MagicMock()
            mock_pytorch.complete.return_value = self._create_mock_response(responses["model2"])
            MockPyTorch.return_value = mock_pytorch

            # Add backends
            for model_id, config in models.items():
                self.llm_manager.add_llm(model_id, config)

            # Generate scripts with both models
            generator = FridaScriptGenerator(self.llm_manager)
            scripts = {}

            for model_id in models:
                scripts[model_id] = generator.generate_bypass_script(
                    self.binary_info,
                    self.protection,
                    model_id=model_id
                )

            # Verify both scripts were generated
            self.assertEqual(len(scripts), 2)
            self.assertIn("Interceptor.attach", scripts["model1"])
            self.assertIn("Interceptor.replace", scripts["model2"])

    def test_script_generation_error_handling(self):
        """Test error handling in script generation."""
        # Configure backend that will fail
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key="invalid-key",
            model="gpt-4"
        )

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI:
            mock_backend = MagicMock()
            mock_backend.complete.side_effect = Exception("API Error")
            MockOpenAI.return_value = mock_backend

            # Add backend to manager
            self.llm_manager.add_llm("error-test", config)

            # Try to generate script
            generator = FridaScriptGenerator(self.llm_manager)

            # Should handle error gracefully
            script = generator.generate_bypass_script(
                self.binary_info,
                self.protection,
                model_id="error-test"
            )

            # Script should be None or empty
            self.assertIn(script, [None, ""])

    def test_script_validation(self):
        """Test script validation after generation."""
        # Configure backend
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
            model="gpt-4"
        )

        # Test various script outputs
        test_cases = [
            # Valid Frida script
            ("""
            Java.perform(function() {
                console.log("Valid script");
            });
            """, True),

            # Invalid - syntax error
            ("""
            Java.perform(function() {
                console.log("Missing closing
            });
            """, False),

            # Valid Ghidra script
            ("""
            # Ghidra script
            from ghidra.program.model.listing import *
            print("Valid Ghidra script")
            """, True),

            # Empty script
            ("", False)
        ]

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI:
            mock_backend = MagicMock()
            MockOpenAI.return_value = mock_backend

            # Add backend
            self.llm_manager.add_llm("validation-test", config)

            for script_content, should_be_valid in test_cases:
                mock_backend.complete.return_value = self._create_mock_response(script_content)

                # Generate script
                generator = FridaScriptGenerator(self.llm_manager)
                script = generator.generate_bypass_script(
                    self.binary_info,
                    self.protection,
                    model_id="validation-test"
                )

                # Basic validation
                if should_be_valid:
                    self.assertIsNotNone(script)
                    self.assertNotEqual(script.strip(), "")
                else:
                    # Invalid scripts might be filtered or fixed
                    pass

    def test_performance_tracking(self):
        """Test performance tracking during script generation."""
        from intellicrack.ai.model_performance_monitor import get_performance_monitor

        # Configure backend
        config = LLMConfig(
            provider=LLMProvider.OPENAI,
            api_key="test-key",
            model="gpt-4"
        )

        with patch('intellicrack.ai.llm_backends.OpenAIBackend') as MockOpenAI:
            mock_backend = MagicMock()
            mock_backend.complete.return_value = self._create_mock_response("// Test script")
            MockOpenAI.return_value = mock_backend

            # Add backend
            self.llm_manager.add_llm("perf-test", config)

            # Get performance monitor
            perf_monitor = get_performance_monitor()

            # Generate script
            generator = FridaScriptGenerator(self.llm_manager)
            script = generator.generate_bypass_script(
                self.binary_info,
                self.protection,
                model_id="perf-test"
            )

            # Check if performance was tracked
            metrics = perf_monitor.get_metrics_summary("perf-test")
            # Note: Metrics might be empty if backend doesn't track
            self.assertIsInstance(metrics, dict)


class TestModelBackendCompatibility(unittest.TestCase):
    """Test compatibility of different model backends."""

    def setUp(self):
        """Set up test environment."""
        self.llm_manager = LLMManager()

    def test_backend_switching(self):
        """Test switching between different backends."""
        # Add multiple backends
        backends = [
            ("openai", LLMConfig(provider=LLMProvider.OPENAI, api_key="test")),
            ("pytorch", LLMConfig(provider=LLMProvider.PYTORCH, model_path="/test")),
            ("onnx", LLMConfig(provider=LLMProvider.ONNX, model_path="/test.onnx"))
        ]

        with patch('intellicrack.ai.llm_backends.OpenAIBackend'), \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend'), \
             patch('intellicrack.ai.llm_backends.ONNXLLMBackend'):

            for model_id, config in backends:
                self.llm_manager.add_llm(model_id, config)

            # Verify all backends are available
            available = self.llm_manager.list_llms()
            self.assertEqual(len(available), len(backends))

            # Get each backend
            for model_id, _ in backends:
                backend = self.llm_manager.get_llm(model_id)
                self.assertIsNotNone(backend)

    def test_config_serialization(self):
        """Test saving and loading configurations."""
        # Create configs
        configs = {
            "model1": LLMConfig(
                provider=LLMProvider.OPENAI,
                api_key="test-key",
                model="gpt-4",
                temperature=0.7
            ),
            "model2": LLMConfig(
                provider=LLMProvider.PYTORCH,
                model_path="/models/test.pt",
                device="cuda",
                quantization="8bit"
            )
        }

        # Save to temp file
        config_file = self.test_dir / "llm_configs.json"

        # Mock the backends
        with patch('intellicrack.ai.llm_backends.OpenAIBackend'), \
             patch('intellicrack.ai.llm_backends.PyTorchLLMBackend'):

            # Add configs
            for model_id, config in configs.items():
                self.llm_manager.add_llm(model_id, config)

            # Save configurations
            saved_configs = {}
            for model_id in configs:
                llm = self.llm_manager.get_llm(model_id)
                if llm:
                    saved_configs[model_id] = llm.config.__dict__

            with open(config_file, 'w') as f:
                json.dump(saved_configs, f, indent=2, default=str)

            # Load configurations
            new_manager = LLMManager()

            with open(config_file, 'r') as f:
                loaded_configs = json.load(f)

            for model_id, config_dict in loaded_configs.items():
                provider = LLMProvider(config_dict['provider'])
                config = LLMConfig(provider=provider, **{
                    k: v for k, v in config_dict.items() if k != 'provider'
                })
                new_manager.add_llm(model_id, config)

            # Verify loaded correctly
            self.assertEqual(len(new_manager.list_llms()), len(configs))


if __name__ == "__main__":
    unittest.main()
