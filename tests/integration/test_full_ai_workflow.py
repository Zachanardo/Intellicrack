"""
Comprehensive Integration Tests for AI Script Generation Workflow

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
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from intellicrack.ai.ai_script_generator import AIScriptGenerator, ScriptType
from intellicrack.ai.autonomous_agent import AutonomousAgent
from intellicrack.ai.intelligent_code_modifier import IntelligentCodeModifier
from intellicrack.ai.llm_backends import LLMManager, LLMResponse
from intellicrack.ai.qemu_test_manager import QemuTestManager
from intellicrack.ui.ai_assistant_enhanced import EnhancedAIAssistant
from intellicrack.utils.logger import get_logger

logger = get_logger(__name__)


@pytest.fixture
def temp_project_dir():
    """Create temporary project directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        project_path = Path(tmpdir)

        # Create sample project structure
        (project_path / "src").mkdir()
        (project_path / "tests").mkdir()
        (project_path / "scripts").mkdir()

        # Sample target binary
        target_binary = project_path / "target.exe"
        target_binary.write_bytes(b"PE\x00\x00" + b"\x90" * 100)  # Minimal PE header

        # Sample Python file for modification
        sample_py = project_path / "src" / "license_checker.py"
        sample_py.write_text("""
def validate_license(key):
    if not key:
        return False
    if len(key) < 16:
        return False
    return key.startswith("LIC-")

class LicenseManager:
    def __init__(self):
        self.valid_keys = set()

    def add_key(self, key):
        if validate_license(key):
            self.valid_keys.add(key)
            return True
        return False
""")

        yield project_path


@pytest.fixture
def mock_llm_manager():
    """Mock LLM manager with realistic responses."""
    manager = Mock(spec=LLMManager)

    # Mock script generation response
    script_response = LLMResponse(
        content="""
```javascript
// Frida script to bypass license validation
Java.perform(function() {
    var LicenseValidator = Java.use("com.example.LicenseValidator");

    LicenseValidator.validateLicense.implementation = function(key) {
        console.log("[+] License validation bypassed for key: " + key);
        return true;  // Always return true
    };

    console.log("[+] License validation hook installed");
});
```
""",
        model="test-model"
    )

    # Mock code modification response
    modification_response = LLMResponse(
        content="""
```json
{
  "modifications": [
    {
      "type": "function_modification",
      "description": "Bypass license validation by always returning true",
      "start_line": 1,
      "end_line": 5,
      "original_code": "def validate_license(key):\\n    if not key:\\n        return False\\n    if len(key) < 16:\\n        return False\\n    return key.startswith(\\"LIC-\\")",
      "modified_code": "def validate_license(key):\\n    # Bypass: Always return True\\n    return True",
      "reasoning": "Modified function to bypass all validation checks",
      "confidence": 0.95,
      "impact": "License validation will always pass"
    }
  ]
}
```
""",
        model="test-model"
    )

    # Mock analysis response
    analysis_response = LLMResponse(
        content="""
The target binary shows typical license validation patterns:
1. String comparison checks for license format
2. Length validation (minimum 16 characters)
3. Prefix checking for "LIC-" pattern

Recommended approach:
- Hook the validation function directly
- Return true regardless of input
- Log bypass for verification

Risk level: Low
Success probability: 95%
""",
        model="test-model"
    )

    manager.chat.side_effect = [script_response, modification_response, analysis_response]
    manager.is_available.return_value = True
    manager.get_available_models.return_value = ["test-model"]

    return manager


class TestFullAIWorkflow:
    """Test complete AI workflow integration."""

    def test_end_to_end_script_generation_and_testing(self, temp_project_dir, mock_llm_manager):
        """Test complete workflow from analysis to script deployment."""

        # 1. Initialize components
        script_generator = AIScriptGenerator(mock_llm_manager)
        qemu_manager = QemuTestManager()
        autonomous_agent = AutonomousAgent(mock_llm_manager)

        target_binary = temp_project_dir / "target.exe"

        # 2. Generate Frida script
        script_request = {
            "target_info": {
                "file_path": str(target_binary),
                "architecture": "x86_64",
                "platform": "windows"
            },
            "bypass_type": "license_validation",
            "requirements": ["Hook validation function", "Always return true"],
            "constraints": ["Don't crash application", "Log bypass activity"]
        }

        scripts = script_generator.generate_frida_script(script_request)
        assert len(scripts) > 0

        generated_script = scripts[0]
        assert "validateLicense" in generated_script.content
        assert "Java.perform" in generated_script.content
        assert generated_script.script_type == ScriptType.FRIDA

        # 3. Test script in QEMU (mocked)
        with patch('intellicrack.core.emulation.qemu_emulator.QemuEmulator') as mock_qemu:
            mock_vm = Mock()
            mock_vm.is_running.return_value = True
            mock_vm.execute_command.return_value = ("Success", 0)
            mock_qemu.return_value = mock_vm

            test_results = qemu_manager.test_script_in_vm(
                generated_script, 
                str(target_binary),
                vm_config={
                    "name": "test_vm",
                    "memory": 2048,
                    "architecture": "x86_64"
                }
            )

            assert test_results["success"] is True
            assert "script_output" in test_results

    def test_autonomous_agent_workflow(self, temp_project_dir, mock_llm_manager):
        """Test autonomous agent analyzing and generating solutions."""

        agent = AutonomousAgent(mock_llm_manager)
        target_binary = temp_project_dir / "target.exe"

        # Configure agent task
        task_config = {
            "objective": "Bypass license validation in target application",
            "target_file": str(target_binary),
            "analysis_depth": "comprehensive",
            "generate_scripts": True,
            "test_scripts": False,  # Skip actual testing
            "max_iterations": 3
        }

        # Run autonomous analysis
        with patch.object(agent, '_analyze_target') as mock_analyze:
            mock_analyze.return_value = {
                "protection_type": "license_validation",
                "complexity": "medium",
                "recommended_approach": "frida_hook",
                "confidence": 0.85
            }

            with patch.object(agent, '_execute_plan') as mock_execute:
                mock_execute.return_value = {
                    "success": True,
                    "scripts_generated": 1,
                    "modifications_applied": 0,
                    "test_results": {"passed": 1, "failed": 0}
                }

                results = agent.execute_autonomous_task(task_config)

                assert results["success"] is True
                assert results["scripts_generated"] > 0
                assert mock_analyze.called
                assert mock_execute.called

    def test_code_modification_integration(self, temp_project_dir, mock_llm_manager):
        """Test code modification system integration."""

        modifier = IntelligentCodeModifier(mock_llm_manager)
        sample_file = temp_project_dir / "src" / "license_checker.py"

        # Create modification request
        request = modifier.create_modification_request(
            description="Bypass license validation in Python code",
            target_files=[str(sample_file)],
            requirements=["Always return True", "Maintain function signature"],
            constraints=["Keep code readable", "Don't break imports"]
        )

        # Analyze and generate changes
        changes = modifier.analyze_modification_request(request)

        assert len(changes) > 0
        change = changes[0]
        assert "bypass" in change.description.lower()
        assert change.confidence > 0.9

        # Preview changes
        preview = modifier.preview_changes([change.change_id])
        assert len(preview["changes"]) == 1
        assert len(preview["files_affected"]) == 1

        # Apply changes
        original_content = sample_file.read_text()
        results = modifier.apply_changes([change.change_id], create_backup=True)

        assert len(results["applied"]) == 1
        assert len(results["backups_created"]) == 1

        # Verify modification
        modified_content = sample_file.read_text()
        assert modified_content != original_content
        assert "return True" in modified_content

    def test_ui_component_integration(self, temp_project_dir, mock_llm_manager):
        """Test UI component integration."""

        # Test enhanced AI assistant
        with patch('PyQt5.QtWidgets.QWidget'):
            assistant = EnhancedAIAssistant(str(temp_project_dir))

            # Test project context loading
            assistant.load_project_context()
            assert assistant.project_root == str(temp_project_dir)

            # Test chat functionality (mocked)
            with patch.object(assistant, 'add_message') as mock_add:
                assistant.send_message("Generate a Frida script to bypass license validation")
                mock_add.assert_called()

    def test_performance_under_load(self, temp_project_dir, mock_llm_manager):
        """Test system performance under load."""

        script_generator = AIScriptGenerator(mock_llm_manager)

        # Generate multiple scripts concurrently
        start_time = time.time()

        scripts = []
        for i in range(5):
            request = {
                "target_info": {
                    "file_path": str(temp_project_dir / f"target_{i}.exe"),
                    "architecture": "x86_64",
                    "platform": "windows"
                },
                "bypass_type": f"protection_type_{i}",
                "requirements": [f"Requirement {i}"],
                "constraints": [f"Constraint {i}"]
            }

            generated = script_generator.generate_frida_script(request)
            scripts.extend(generated)

        end_time = time.time()
        generation_time = end_time - start_time

        # Performance assertions
        assert len(scripts) == 5
        assert generation_time < 10.0  # Should complete within 10 seconds
        assert all(script.content for script in scripts)  # All scripts have content

    def test_error_handling_and_recovery(self, temp_project_dir, mock_llm_manager):
        """Test error handling and recovery mechanisms."""

        # Test with failing LLM
        failing_llm = Mock(spec=LLMManager)
        failing_llm.chat.side_effect = Exception("LLM service unavailable")
        failing_llm.is_available.return_value = False

        script_generator = AIScriptGenerator(failing_llm)

        # Should handle LLM failure gracefully
        request = {
            "target_info": {"file_path": str(temp_project_dir / "target.exe")},
            "bypass_type": "test"
        }

        scripts = script_generator.generate_frida_script(request)
        # Should return empty list or fallback scripts
        assert isinstance(scripts, list)

        # Test code modifier with invalid file
        modifier = IntelligentCodeModifier(mock_llm_manager)

        request = modifier.create_modification_request(
            description="Test modification",
            target_files=["/nonexistent/file.py"]
        )

        # Should handle gracefully
        changes = modifier.analyze_modification_request(request)
        assert isinstance(changes, list)  # Should not crash

    def test_integration_with_existing_tools(self, temp_project_dir, mock_llm_manager):
        """Test integration with existing Intellicrack tools."""

        # Test integration with binary analysis

        target_binary = temp_project_dir / "target.exe"

        # Mock binary analysis
        with patch('intellicrack.utils.binary_analysis.analyze_binary') as mock_analyze:
            mock_analyze.return_value = {
                "architecture": "x86_64",
                "platform": "windows",
                "protections": ["license_check"],
                "entry_points": ["0x401000"],
                "imports": ["kernel32.dll", "user32.dll"]
            }

            script_generator = AIScriptGenerator(mock_llm_manager)

            # Use analysis results in script generation
            analysis = mock_analyze(str(target_binary))

            request = {
                "target_info": analysis,
                "bypass_type": analysis["protections"][0],
                "requirements": ["Use analysis data"]
            }

            scripts = script_generator.generate_frida_script(request)
            assert len(scripts) > 0

            # Verify analysis was used
            mock_analyze.assert_called_once()

    def test_script_validation_and_quality_checks(self, temp_project_dir, mock_llm_manager):
        """Test script validation and quality assurance."""

        script_generator = AIScriptGenerator(mock_llm_manager)

        # Generate script
        request = {
            "target_info": {"file_path": str(temp_project_dir / "target.exe")},
            "bypass_type": "license_validation"
        }

        scripts = script_generator.generate_frida_script(request)
        assert len(scripts) > 0

        script = scripts[0]

        # Quality checks
        assert len(script.content) > 50  # Substantial content
        assert "Java.perform" in script.content  # Proper Frida structure
        assert script.estimated_success_rate > 0.0  # Has success estimate
        assert script.risk_level in ["low", "medium", "high"]  # Valid risk level

        # Syntax validation for JavaScript
        try:
            # Basic syntax check - no obvious syntax errors
            assert script.content.count('{') == script.content.count('}')
            assert script.content.count('(') == script.content.count(')')
        except AssertionError:
            pytest.fail("Generated script has syntax issues")

    @pytest.mark.asyncio
    async def test_async_operations(self, temp_project_dir, mock_llm_manager):
        """Test asynchronous operations in the workflow."""

        # Test concurrent script generation
        script_generator = AIScriptGenerator(mock_llm_manager)

        async def generate_script_async(request):
            """Simulate async script generation."""
            await asyncio.sleep(0.1)  # Simulate processing time
            return script_generator.generate_frida_script(request)

        # Generate multiple scripts concurrently
        requests = [
            {
                "target_info": {"file_path": str(temp_project_dir / f"target_{i}.exe")},
                "bypass_type": f"type_{i}"
            }
            for i in range(3)
        ]

        tasks = [generate_script_async(req) for req in requests]
        results = await asyncio.gather(*tasks)

        assert len(results) == 3
        assert all(isinstance(result, list) for result in results)

    def test_memory_usage_optimization(self, temp_project_dir, mock_llm_manager):
        """Test memory usage optimization."""

        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Create multiple components
        components = []
        for i in range(10):
            script_generator = AIScriptGenerator(mock_llm_manager)
            modifier = IntelligentCodeModifier(mock_llm_manager)
            components.extend([script_generator, modifier])

        # Generate some work
        for i, component in enumerate(components[:5]):
            if hasattr(component, 'generate_frida_script'):
                request = {
                    "target_info": {"file_path": str(temp_project_dir / "target.exe")},
                    "bypass_type": "test"
                }
                component.generate_frida_script(request)

        # Check memory usage
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory

        # Memory increase should be reasonable (less than 100MB)
        assert memory_increase < 100 * 1024 * 1024, f"Memory usage increased by {memory_increase / 1024 / 1024:.2f}MB"

        # Cleanup
        del components