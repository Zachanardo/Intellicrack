"""
Unit tests for AI Script Generator with REAL script generation.
Tests REAL Frida and Ghidra script generation using actual AI models.
NO MOCKS - ALL TESTS GENERATE REAL, WORKING SCRIPTS.
"""

import pytest
from pathlib import Path
import tempfile
import subprocess
import json

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from tests.base_test import IntellicrackTestBase


class TestAIScriptGenerator(IntellicrackTestBase):
    """Test AI script generation with REAL outputs."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with real AI script generator."""
        self.generator = AIScriptGenerator()
        self.temp_dir = Path(tempfile.mkdtemp())
        self.binary_analyzer = BinaryAnalyzer()
        
        # Get real test binaries
        self.test_binaries_dir = Path("tests/fixtures/binaries")
        if not self.test_binaries_dir.exists():
            self.test_binaries_dir = Path("C:/Intellicrack/tests/fixtures/binaries")
            
    def teardown_method(self):
        """Clean up temp files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def test_frida_script_generation_basic(self):
        """Test basic Frida script generation with REAL output."""
        # Generate script for API hooking
        prompt = "Generate a Frida script to hook MessageBoxA on Windows"
        
        script = self.generator.generate_frida_script(prompt)
        
        self.assert_real_output(script)
        
        # Validate script structure
        assert "Interceptor.attach" in script
        assert "MessageBoxA" in script
        assert "onEnter" in script or "onLeave" in script
        
        # Script should be valid JavaScript
        assert not script.startswith("TODO")
        assert not script.startswith("PLACEHOLDER")
        assert "function" in script or "=>" in script
        
    def test_frida_script_generation_advanced(self):
        """Test advanced Frida script generation."""
        # Test different script types
        test_cases = [
            {
                "prompt": "Hook and log all file operations (CreateFile, ReadFile, WriteFile)",
                "expected": ["CreateFile", "ReadFile", "WriteFile", "Interceptor.attach"]
            },
            {
                "prompt": "Bypass anti-debugging checks in CheckRemoteDebuggerPresent",
                "expected": ["CheckRemoteDebuggerPresent", "retval.replace", "0x0"]
            },
            {
                "prompt": "Trace all crypto API calls and dump parameters",
                "expected": ["Crypt", "console.log", "args["]
            },
            {
                "prompt": "Hook socket operations and modify network traffic",
                "expected": ["send", "recv", "Memory.read", "Memory.write"]
            }
        ]
        
        for test in test_cases:
            script = self.generator.generate_frida_script(test["prompt"])
            
            self.assert_real_output(script)
            
            # Check for expected elements
            for expected in test["expected"]:
                assert expected in script, f"Expected '{expected}' in script for: {test['prompt']}"
                
            # Validate it's real code
            assert len(script) > 100  # Real scripts are substantial
            assert script.count("{") == script.count("}")  # Balanced braces
            
    def test_ghidra_script_generation_basic(self):
        """Test basic Ghidra script generation with REAL output."""
        prompt = "Generate a Ghidra script to find all XOR encryption loops"
        
        script = self.generator.generate_ghidra_script(prompt)
        
        self.assert_real_output(script)
        
        # Validate Ghidra script structure
        assert "import ghidra" in script or "from ghidra" in script
        assert "currentProgram" in script or "getCurrentProgram()" in script
        assert "def " in script or "class " in script
        
        # Should be valid Python
        assert not script.startswith("TODO")
        assert not script.startswith("PLACEHOLDER")
        
    def test_ghidra_script_generation_analysis(self):
        """Test Ghidra analysis script generation."""
        test_cases = [
            {
                "prompt": "Find and label all crypto constants (AES S-boxes, DES permutations)",
                "expected": ["0x63", "0x7c", "createLabel", "crypto_constant"]
            },
            {
                "prompt": "Identify and rename all vtable structures",
                "expected": ["DataType", "Structure", "vtable", "pointer"]
            },
            {
                "prompt": "Analyze call graph and find dead code",
                "expected": ["getReferencesTo", "Function", "dead_code", "unreachable"]
            },
            {
                "prompt": "Deobfuscate strings using custom decryption",
                "expected": ["getString", "decrypt", "createBookmark", "deobfuscated"]
            }
        ]
        
        for test in test_cases:
            script = self.generator.generate_ghidra_script(test["prompt"])
            
            self.assert_real_output(script)
            
            # Check for expected elements
            for expected in test["expected"]:
                assert expected in script, f"Expected '{expected}' in script for: {test['prompt']}"
                
            # Validate it's real Python code
            assert len(script) > 150  # Real analysis scripts are substantial
            
    def test_binary_specific_script_generation(self):
        """Test script generation for specific binary analysis."""
        # Get a real test binary
        test_binary = None
        for binary in self.test_binaries_dir.glob("*.exe"):
            test_binary = binary
            break
            
        if not test_binary:
            pytest.skip("No test binaries available")
            
        # Analyze binary first
        analysis = self.binary_analyzer.analyze(test_binary)
        
        # Generate targeted Frida script
        prompt = f"Generate Frida script for binary with imports: {', '.join(analysis.get('imports', [])[:5])}"
        
        script = self.generator.generate_frida_script(
            prompt,
            binary_info=analysis
        )
        
        self.assert_real_output(script)
        
        # Script should reference actual imports
        if 'imports' in analysis and analysis['imports']:
            import_found = False
            for imp in analysis['imports'][:5]:
                if imp in script:
                    import_found = True
                    break
            assert import_found, "Script should reference actual binary imports"
            
    def test_script_syntax_validation(self):
        """Test that generated scripts have valid syntax."""
        # Test Frida script syntax
        frida_script = self.generator.generate_frida_script(
            "Hook all registry operations"
        )
        
        # Save and check with Node.js
        frida_file = self.temp_dir / "test_frida.js"
        frida_file.write_text(frida_script)
        
        # Basic syntax check - should not throw errors
        try:
            result = subprocess.run(
                ["node", "--check", str(frida_file)],
                capture_output=True,
                text=True,
                timeout=5
            )
            assert result.returncode == 0, f"Frida script has syntax errors: {result.stderr}"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Node.js not available, do basic validation
            assert frida_script.count("{") == frida_script.count("}")
            assert frida_script.count("(") == frida_script.count(")")
            
        # Test Ghidra script syntax
        ghidra_script = self.generator.generate_ghidra_script(
            "Find all stack strings"
        )
        
        # Basic Python syntax check
        try:
            compile(ghidra_script, '<string>', 'exec')
        except SyntaxError as e:
            pytest.fail(f"Ghidra script has syntax error: {e}")
            
    def test_multi_model_generation(self):
        """Test script generation with multiple AI models."""
        prompt = "Generate Frida script to bypass certificate pinning"
        
        # Try different models
        models = self.generator.list_available_models()
        
        if len(models) < 2:
            pytest.skip("Multiple models not available")
            
        scripts = []
        for model in models[:2]:  # Test first two models
            script = self.generator.generate_frida_script(
                prompt,
                model=model
            )
            scripts.append(script)
            
        # All should be valid scripts
        for script in scripts:
            self.assert_real_output(script)
            assert "certificate" in script.lower() or "ssl" in script.lower()
            assert "Interceptor" in script
            
    def test_script_customization_options(self):
        """Test script generation with customization options."""
        options = {
            "target_process": "notepad.exe",
            "verbose_logging": True,
            "error_handling": True,
            "performance_monitoring": True
        }
        
        script = self.generator.generate_frida_script(
            "Monitor file operations",
            options=options
        )
        
        self.assert_real_output(script)
        
        # Check customizations applied
        assert "notepad.exe" in script
        assert "console.log" in script  # Verbose logging
        assert "try" in script or "catch" in script  # Error handling
        assert "Date.now()" in script or "performance" in script  # Performance monitoring
        
    def test_exploit_script_generation(self):
        """Test exploit development script generation."""
        # Generate scripts for exploit development
        prompts = [
            "Generate Frida script to find ROP gadgets",
            "Create script to bypass ASLR and find base addresses",
            "Generate heap spray monitoring script"
        ]
        
        for prompt in prompts:
            script = self.generator.generate_frida_script(prompt)
            
            self.assert_real_output(script)
            assert len(script) > 200  # Exploit scripts are complex
            
            # Should contain relevant exploit development code
            if "ROP" in prompt:
                assert "gadget" in script.lower() or "ret" in script
            elif "ASLR" in prompt:
                assert "base" in script.lower() or "module" in script.lower()
            elif "heap" in prompt:
                assert "alloc" in script.lower() or "heap" in script.lower()
                
    def test_protection_bypass_scripts(self):
        """Test protection bypass script generation."""
        protection_types = [
            ("anti-VM detection", ["VMware", "VirtualBox", "hypervisor"]),
            ("packer detection", ["UPX", "packed", "entropy"]),
            ("anti-tamper", ["integrity", "checksum", "CRC"]),
            ("license checks", ["license", "serial", "activation"])
        ]
        
        for protection, keywords in protection_types:
            script = self.generator.generate_frida_script(
                f"Bypass {protection}"
            )
            
            self.assert_real_output(script)
            
            # Should contain relevant bypass code
            keyword_found = False
            for keyword in keywords:
                if keyword.lower() in script.lower():
                    keyword_found = True
                    break
            assert keyword_found, f"Script for {protection} should contain relevant keywords"
            
    def test_script_template_system(self):
        """Test script template system."""
        # Test getting available templates
        templates = self.generator.get_script_templates()
        
        assert len(templates) > 0
        assert all('name' in t and 'description' in t for t in templates)
        
        # Generate from template
        if templates:
            template_name = templates[0]['name']
            script = self.generator.generate_from_template(
                template_name,
                parameters={
                    "function_name": "CreateFileW",
                    "module_name": "kernel32.dll"
                }
            )
            
            self.assert_real_output(script)
            assert "CreateFileW" in script
            assert "kernel32" in script.lower()
            
    def test_script_optimization(self):
        """Test script optimization for performance."""
        # Generate unoptimized script
        script = self.generator.generate_frida_script(
            "Hook all API calls in module",
            options={"optimize": False}
        )
        
        # Generate optimized version
        optimized = self.generator.generate_frida_script(
            "Hook all API calls in module",
            options={"optimize": True}
        )
        
        self.assert_real_output(script)
        self.assert_real_output(optimized)
        
        # Optimized should be different and potentially more efficient
        assert script != optimized
        
        # Optimized might use batch operations, caching, etc.
        optimization_indicators = [
            "cache", "batch", "buffer", "async", "Promise", "Map", "Set"
        ]
        
        optimization_found = any(
            indicator in optimized for indicator in optimization_indicators
        )
        assert optimization_found, "Optimized script should use performance techniques"
        
    def test_error_recovery_in_scripts(self):
        """Test that generated scripts include error recovery."""
        script = self.generator.generate_frida_script(
            "Complex hooking with error recovery"
        )
        
        self.assert_real_output(script)
        
        # Should include error handling
        assert "try" in script
        assert "catch" in script
        assert "console.error" in script or "console.warn" in script
        
        # Should handle common edge cases
        edge_cases = ["null", "undefined", "length", "hasOwnProperty"]
        edge_case_found = any(case in script for case in edge_cases)
        assert edge_case_found, "Script should handle edge cases"
        
    def test_script_documentation_generation(self):
        """Test that scripts include proper documentation."""
        script = self.generator.generate_frida_script(
            "Well-documented API monitor",
            options={"include_docs": True}
        )
        
        self.assert_real_output(script)
        
        # Should include comments
        assert "//" in script or "/*" in script
        
        # Should document parameters, return values, etc.
        doc_keywords = ["@param", "@return", "Usage:", "Example:", "Note:"]
        doc_found = any(keyword in script for keyword in doc_keywords)
        assert doc_found, "Script should include documentation"
        
    def test_platform_specific_scripts(self):
        """Test platform-specific script generation."""
        platforms = [
            ("Windows", ["kernel32", "ntdll", "WINAPI"]),
            ("Linux", ["libc", "syscall", "LD_PRELOAD"]),
            ("Android", ["Java.perform", "dalvik", "ART"]),
            ("iOS", ["ObjC", "dyld", "substrate"])
        ]
        
        for platform, indicators in platforms:
            script = self.generator.generate_frida_script(
                f"Hook system calls on {platform}",
                platform=platform
            )
            
            self.assert_real_output(script)
            
            # Should contain platform-specific code
            indicator_found = any(
                indicator in script for indicator in indicators
            )
            assert indicator_found, f"Script for {platform} should contain platform-specific code"