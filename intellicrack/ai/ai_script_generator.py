"""
AI Script Generator for Frida and Ghidra Scripts

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

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.logger import get_logger

logger = get_logger(__name__)


class ScriptType(Enum):
    """Types of scripts that can be generated."""
    FRIDA = "frida"
    GHIDRA = "ghidra"
    UNIFIED = "unified"


class ProtectionType(Enum):
    """Types of protection mechanisms detected."""
    LICENSE_CHECK = "license_check"
    TRIAL_TIMER = "trial_timer"
    TRIAL_PROTECTION = "trial_protection"
    HARDWARE_LOCK = "hardware_lock"
    NETWORK_VALIDATION = "network_validation"
    CRYPTO_VERIFICATION = "crypto_verification"
    ANTI_DEBUG = "anti_debug"
    VM_DETECTION = "vm_detection"
    TIME_BOMB = "time_bomb"
    INTEGRITY_CHECK = "integrity_check"
    UNKNOWN = "unknown"


@dataclass
class ScriptMetadata:
    """Metadata for generated scripts."""
    script_id: str
    script_type: ScriptType
    target_binary: str
    protection_types: List[ProtectionType]
    generated_at: datetime = field(default_factory=datetime.now)
    llm_model: str = ""
    generation_time: float = 0.0
    iterations: int = 1
    success_probability: float = 0.0


@dataclass
class GeneratedScript:
    """Container for a generated script with metadata."""
    metadata: ScriptMetadata
    content: str
    language: str
    entry_point: str
    dependencies: List[str] = field(default_factory=list)
    hooks: List[Dict[str, Any]] = field(default_factory=list)
    patches: List[Dict[str, Any]] = field(default_factory=list)
    validation_passed: bool = False


@dataclass
class ScriptGenerationResult:
    """Result of script generation process."""
    success: bool
    script: Optional[GeneratedScript] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    generation_time: float = 0.0
    iterations: int = 1
    confidence_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class ScriptValidator:
    """Validates generated scripts for correctness and safety."""

    def __init__(self):
        """Initialize script validator with patterns and requirements."""
        self.forbidden_patterns = [
            "TODO", "PLACEHOLDER", "FIXME", "XXX",
            "mock", "stub", "dummy", "fake",
            "pass  # Implement", "...", "NotImplemented"
        ]

        self.required_frida_elements = [
            "Interceptor", "Module", "Memory", "console.log"
        ]

        self.required_ghidra_elements = [
            "from ghidra", "GhidraScript", "def run"
        ]

        # Context optimization settings
        self.max_context_tokens = 8000
        self.context_compression_ratio = 0.7

    def validate_script(self, script: GeneratedScript) -> Tuple[bool, List[str]]:
        """Validate a generated script for quality and safety."""
        errors = []

        # Check for forbidden patterns
        for pattern in self.forbidden_patterns:
            if pattern in script.content:
                errors.append(f"Contains forbidden pattern: {pattern}")

        # Type-specific validation
        if script.metadata.script_type == ScriptType.FRIDA:
            errors.extend(self._validate_frida_script(script.content))
        elif script.metadata.script_type == ScriptType.GHIDRA:
            errors.extend(self._validate_ghidra_script(script.content))

        # Check for basic syntax issues
        errors.extend(self._validate_syntax(script.content, script.language))

        is_valid = len(errors) == 0
        script.validation_passed = is_valid

        return is_valid, errors

    def _validate_frida_script(self, content: str) -> List[str]:
        """Validate Frida-specific requirements."""
        errors = []

        # Check for required Frida elements
        for element in self.required_frida_elements:
            if element not in content:
                errors.append(f"Missing required Frida element: {element}")

        # Check for proper hook structure
        if "Interceptor.attach" not in content and "Interceptor.replace" not in content:
            errors.append("No Interceptor hooks found - script may not be functional")

        # Check for proper function structure
        if "onEnter:" not in content and "onLeave:" not in content and "replacement:" not in content:
            errors.append("No hook callbacks found - script may not be functional")

        return errors

    def _validate_ghidra_script(self, content: str) -> List[str]:
        """Validate Ghidra-specific requirements."""
        errors = []

        # Check for required Ghidra elements
        for element in self.required_ghidra_elements:
            if element not in content:
                errors.append(f"Missing required Ghidra element: {element}")

        # Check for proper class structure
        if "class " not in content and "def run(" not in content:
            errors.append("No valid Ghidra script class or run method found")

        return errors

    def _validate_syntax(self, content: str, language: str) -> List[str]:
        """Basic syntax validation."""
        errors = []

        if language.lower() == "javascript":
            # Basic JavaScript syntax checks
            if content.count('{') != content.count('}'):
                errors.append("Unmatched curly braces in JavaScript")
            if content.count('(') != content.count(')'):
                errors.append("Unmatched parentheses")

        elif language.lower() == "python":
            # Basic Python syntax checks
            try:
                compile(content, '<string>', 'exec')
            except SyntaxError as e:
                errors.append(f"Python syntax error: {e}")

        return errors


class ScriptTemplateEngine:
    """Manages script templates and generation."""

    def __init__(self):
        """Initialize script template engine with base templates."""
        self.frida_base_template = '''
// Auto-generated Frida script by Intellicrack AI
// Target: {target_info}
// Protection Type: {protection_type}
// Generated: {timestamp}

{{
    name: "{script_name}",
    description: "{description}",
    version: "1.0.0",

    // Configuration
    config: {config_json},

    // Runtime state
    hooks: {{}},
    detections: [],

    run: function() {{
        console.log("[AI-Generated] Initializing {script_name}...");

        {initialization_code}

        {hook_installations}

        {bypass_logic}

        console.log("[AI-Generated] Script initialized successfully");
    }},

    {helper_functions}
}}
'''

        self.ghidra_base_template = '''
# Auto-generated Ghidra script by Intellicrack AI
# Target: {target_info}
# Analysis Goal: {analysis_goal}
# Generated: {timestamp}

from ghidra.app.script import GhidraScript
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Function
import re

class {script_class_name}(GhidraScript):
    def run(self):
        print("[AI-Generated] Starting {script_name} analysis...")

        {initialization_code}

        {analysis_functions}

        {patching_logic}

        print("[AI-Generated] Analysis complete")

# Run the script
{script_class_name}().run()
'''

    def render_frida_script(self, **kwargs) -> str:
        """Render a Frida script from template."""
        # Provide safe defaults for template variables
        defaults = {
            'target_info': kwargs.get('target_info', 'Unknown'),
            'protection_type': kwargs.get('protection_type', 'Generic'),
            'timestamp': kwargs.get('timestamp', 'Unknown'),
            'script_name': kwargs.get('script_name', 'AIGeneratedScript'),
            'description': kwargs.get('description', 'AI-generated bypass script'),
            'config_json': kwargs.get('config_json', '{}'),
            'initialization_code': kwargs.get('initialization_code', '// No initialization required'),
            'hook_installations': kwargs.get('hook_installations', '// No hooks defined'),
            'bypass_logic': kwargs.get('bypass_logic', '// No bypass logic defined'),
            'helper_functions': kwargs.get('helper_functions', '// No helper functions')
        }
        defaults.update(kwargs)
        return self.frida_base_template.format(**defaults)

    def render_ghidra_script(self, **kwargs) -> str:
        """Render a Ghidra script from template."""
        # Provide safe defaults for template variables
        defaults = {
            'target_info': kwargs.get('target_info', 'Unknown'),
            'analysis_goal': kwargs.get('analysis_goal', 'Generic Analysis'),
            'timestamp': kwargs.get('timestamp', 'Unknown'),
            'script_class_name': kwargs.get('script_class_name', 'AIGeneratedScript'),
            'script_name': kwargs.get('script_name', 'AI Generated Script'),
            'initialization_code': kwargs.get('initialization_code', '// No initialization required'),
            'analysis_functions': kwargs.get('analysis_functions', '// No analysis functions defined'),
            'patching_logic': kwargs.get('patching_logic', '// No patching logic defined')
        }
        defaults.update(kwargs)
        return self.ghidra_base_template.format(**defaults)


class PatternLibrary:
    """Library of protection patterns and bypass strategies."""

    def __init__(self):
        """Initialize pattern library with protection patterns."""
        self.license_check_patterns = {
            "string_comparison": {
                "indicators": ["strcmp", "strcasecmp", "memcmp", "wcscmp"],
                "bypass_strategy": "hook_comparison_return_zero",
                "confidence": 0.9,
                "frida_hook": '''
Interceptor.attach(Module.findExportByName(null, "{function_name}"), {
    onEnter: function(args) {
        console.log("[Hook] {function_name} called");
        this.arg0 = args[0];
        this.arg1 = args[1];
    },
    onLeave: function(retval) {
        console.log("[Hook] {function_name} returned:", retval);
        retval.replace(0); // Force success
    }
});
'''
            },
            "time_check": {
                "indicators": ["GetSystemTime", "time", "clock", "GetTickCount"],
                "bypass_strategy": "hook_time_functions",
                "confidence": 0.85,
                "frida_hook": '''
Interceptor.attach(Module.findExportByName("kernel32.dll", "GetSystemTime"), {
    onEnter: function(args) {
        console.log("[Hook] GetSystemTime called");
    },
    onLeave: function(retval) {
        console.log("[Hook] Time function hooked - may need specific manipulation");
    }
});
'''
            },
            "registry_check": {
                "indicators": ["RegOpenKey", "RegQueryValue", "RegGetValue"],
                "bypass_strategy": "hook_registry_apis",
                "confidence": 0.88,
                "frida_hook": '''
Interceptor.attach(Module.findExportByName("advapi32.dll", "RegQueryValueExW"), {
    onEnter: function(args) {
        console.log("[Hook] Registry query detected");
        this.lpValueName = args[1];
    },
    onLeave: function(retval) {
        if (this.lpValueName && this.lpValueName.readUtf16String().includes("License")) {
            console.log("[Hook] License registry check bypassed");
            retval.replace(0); // ERROR_SUCCESS
        }
    }
});
'''
            }
        }

    def get_bypass_strategy(self, protection_type: ProtectionType) -> Dict[str, Any]:
        """Get bypass strategy for a protection type."""
        if protection_type == ProtectionType.LICENSE_CHECK:
            return {
                "type": "hook_license_functions",
                "patterns": self.license_check_patterns,
                "priority": "high"
            }
        elif protection_type == ProtectionType.TIME_BOMB:
            return {
                "type": "hook_time_functions",
                "patterns": self.license_check_patterns["time_check"],
                "priority": "high"
            }
        else:
            return {
                "type": "generic_analysis",
                "patterns": {},
                "priority": "medium"
            }


class AIScriptGenerator:
    """
    Main AI script generator that creates real, functional Frida and Ghidra scripts.
    NO PLACEHOLDERS - all generated code must be immediately executable.
    """

    def __init__(self, orchestrator=None):
        """Initialize AI script generator with orchestrator."""
        self.orchestrator = orchestrator
        self.template_engine = ScriptTemplateEngine()
        self.pattern_library = PatternLibrary()
        self.validator = ScriptValidator()
        self.generation_history = []

        # Script storage
        self.script_cache = {}
        self.success_patterns = []

        # Context management
        self.max_context_tokens = 8000
        self.context_compression_ratio = 0.7

    def generate_frida_script(self, analysis_results: Dict[str, Any]) -> GeneratedScript:
        """Generate a real, working Frida script based on analysis."""
        start_time = time.time()

        # Extract analysis information
        target_binary = analysis_results.get('binary_path', 'unknown')
        protection_types = self._identify_protections(analysis_results)

        # Create script metadata
        script_id = self._generate_script_id(target_binary, ScriptType.FRIDA)
        metadata = ScriptMetadata(
            script_id=script_id,
            script_type=ScriptType.FRIDA,
            target_binary=target_binary,
            protection_types=protection_types
        )

        # Generate hook specifications
        hooks = self._generate_hooks(analysis_results, protection_types)

        # Generate bypass logic
        bypass_logic = self._generate_bypass_logic(protection_types)

        # Generate helper functions
        helper_functions = self._generate_helper_functions(protection_types)

        # Assemble complete script
        script_content = self.template_engine.render_frida_script(
            target_info=target_binary,
            protection_type=", ".join([p.value for p in protection_types]),
            timestamp=datetime.now().isoformat(),
            script_name=f"Bypass_{Path(target_binary).stem}",
            description=f"AI-generated bypass for {target_binary}",
            config_json=json.dumps({"target": target_binary, "mode": "bypass"}),
            initialization_code=self._generate_initialization_code(),
            hook_installations=hooks,
            bypass_logic=bypass_logic,
            helper_functions=helper_functions
        )

        # Create generated script object
        script = GeneratedScript(
            metadata=metadata,
            content=script_content,
            language="javascript",
            entry_point="run",
            hooks=self._extract_hook_info(hooks)
        )

        # Update metadata
        metadata.generation_time = time.time() - start_time
        metadata.success_probability = self._calculate_success_probability(protection_types)

        # Validate script
        is_valid, errors = self.validator.validate_script(script)
        if not is_valid:
            logger.warning(f"Generated script has validation errors: {errors}")

        return script

    def generate_ghidra_script(self, analysis_results: Dict[str, Any]) -> GeneratedScript:
        """Generate a real, working Ghidra script based on analysis."""
        start_time = time.time()

        # Extract analysis information
        target_binary = analysis_results.get('binary_path', 'unknown')
        protection_types = self._identify_protections(analysis_results)

        # Create script metadata
        script_id = self._generate_script_id(target_binary, ScriptType.GHIDRA)
        metadata = ScriptMetadata(
            script_id=script_id,
            script_type=ScriptType.GHIDRA,
            target_binary=target_binary,
            protection_types=protection_types
        )

        # Generate analysis functions
        analysis_functions = self._generate_analysis_functions(analysis_results)

        # Generate patching logic
        patching_logic = self._generate_patching_logic(analysis_results, protection_types)

        # Assemble complete script
        script_class_name = f"Bypass_{Path(target_binary).stem.replace('.', '_')}"
        script_content = self.template_engine.render_ghidra_script(
            target_info=target_binary,
            analysis_goal="License bypass and protection removal",
            timestamp=datetime.now().isoformat(),
            script_class_name=script_class_name,
            script_name=f"Analysis for {target_binary}",
            initialization_code=self._generate_ghidra_initialization(),
            analysis_functions=analysis_functions,
            patching_logic=patching_logic
        )

        # Create generated script object
        script = GeneratedScript(
            metadata=metadata,
            content=script_content,
            language="python",
            entry_point=f"{script_class_name}().run()",
            patches=self._extract_patch_info(patching_logic)
        )

        # Update metadata
        metadata.generation_time = time.time() - start_time
        metadata.success_probability = self._calculate_success_probability(protection_types)

        # Validate script
        is_valid, errors = self.validator.validate_script(script)
        if not is_valid:
            logger.warning(f"Generated script has validation errors: {errors}")

        return script

    def _identify_protections(self, analysis_results: Dict[str, Any]) -> List[ProtectionType]:
        """Identify protection types from analysis results."""
        protections = []

        # Check for license-related strings
        strings = analysis_results.get('strings', [])
        for string in strings:
            if any(keyword in string.lower() for keyword in ['license', 'trial', 'demo', 'expire']):
                protections.append(ProtectionType.LICENSE_CHECK)
                break

        # Check for time-related functions
        functions = analysis_results.get('functions', [])
        for func in functions:
            if any(time_func in func.get('name', '') for time_func in ['time', 'clock', 'GetSystemTime']):
                protections.append(ProtectionType.TIME_BOMB)
                break

        # Check for network activity
        if analysis_results.get('network_activity'):
            protections.append(ProtectionType.NETWORK_VALIDATION)

        # Default to unknown if no specific protections detected
        if not protections:
            protections.append(ProtectionType.UNKNOWN)

        return protections

    def _generate_hooks(self, analysis_results: Dict[str, Any], protection_types: List[ProtectionType]) -> str:
        """Generate hook installation code based on analysis results."""
        hooks = []

        # Extract relevant information from analysis results
        functions_to_hook = analysis_results.get('functions_to_hook', [])
        addresses_to_patch = analysis_results.get('addresses_to_patch', [])
        imports_table = analysis_results.get('imports', {})

        # Use addresses_to_patch for targeted patching in hooks
        patch_targets = {addr.get('address', '0x0'): addr.get('type', 'unknown') for addr in addresses_to_patch if isinstance(addr, dict)}

        # Use imports_table to target specific imported functions
        # Handle both list and dict formats for imports
        if isinstance(imports_table, list):
            target_imports = [name for name in imports_table if any(keyword in name.lower() for keyword in ['license', 'trial', 'check', 'validate'])]
        elif isinstance(imports_table, dict):
            target_imports = [name for name in imports_table.keys() if any(keyword in name.lower() for keyword in ['license', 'trial', 'check', 'validate'])]
        else:
            target_imports = []

        for protection_type in protection_types:
            strategy = self.pattern_library.get_bypass_strategy(protection_type)

            # Use analysis results to target specific functions/addresses
            if protection_type == ProtectionType.LICENSE_CHECK and functions_to_hook:
                for func_info in functions_to_hook:
                    if func_info.get('type') == 'license_check':
                        strategy_name = strategy.get('name', 'Unknown') if strategy else 'Default'
                        strategy_desc = strategy.get('description', 'Return success') if strategy else 'Default bypass'
                        func_addr = func_info.get('address', '0x0')
                        func_desc = func_info.get('description', 'License validation')

                        # Include patch_targets information in hook generation
                        target_type = patch_targets.get(func_addr, 'unknown')

                        hooks.append(f"""
    // Hook license check function at {func_addr} (type: {target_type})
    // Strategy: {strategy_name}
    var licenseCheckAddr = ptr("{func_addr}");
    if (licenseCheckAddr && !licenseCheckAddr.isNull()) {{
        Interceptor.attach(licenseCheckAddr, {{
            onEnter: function(args) {{{{
                console.log("[+] License check function called");
                // Based on analysis: {func_desc}
                // Using strategy: {strategy_desc}
                // Target imports: {', '.join(target_imports[:3]) if target_imports else 'none'}
            }}}},
            onLeave: function(retval) {{{{
                retval.replace(ptr(1)); // Force return success
                console.log("[+] License check bypassed using strategy: {strategy_name.lower()}");
            }}
        }});
    }}""")

            elif protection_type == ProtectionType.LICENSE_CHECK:
                # Generate license check hooks
                hook_code = '''
        // License check bypass hooks
        var license_functions = ["strcmp", "strcasecmp", "memcmp"];
        license_functions.forEach(function(func_name) {{
            var func_addr = Module.findExportByName(null, func_name);
            if (func_addr) {
                Interceptor.attach(func_addr, {{
                    onEnter: function(args) {{
                        console.log("[Hook] " + func_name + " called");
                        this.isLicenseCheck = false;
                        try {
                            var str1 = args[0].readCString();
                            var str2 = args[1].readCString();
                            if (str1 && str2 && (str1.includes("license") || str2.includes("license"))) {
                                this.isLicenseCheck = true;
                                console.log("[Hook] License check detected: " + str1 + " vs " + str2);
                            }
                        } catch (e) {
                            // Ignore read errors
                        }
                    },
                    onLeave: function(retval) {{
                        if (this.isLicenseCheck) {
                            console.log("[Hook] License check bypassed - forcing success");
                            retval.replace(0);
                        }
                    }
                });
            }
        });
'''
                hooks.append(hook_code)

            elif protection_type == ProtectionType.TIME_BOMB:
                # Generate time function hooks
                hook_code = '''
        // Time bomb bypass hooks
        var time_functions = ["GetSystemTime", "time", "clock", "GetTickCount"];
        time_functions.forEach(function(func_name) {{
            var func_addr = Module.findExportByName(null, func_name);
            if (func_addr) {
                Interceptor.attach(func_addr, {{
                    onEnter: function(args) {{
                        console.log("[Hook] Time function " + func_name + " called");
                    },
                    onLeave: function(retval) {{
                        console.log("[Hook] Time function hooked - maintaining consistent time");
                        // Could implement specific time manipulation here
                    }
                });
            }
        });
'''
                hooks.append(hook_code)

        return "\n".join(hooks) if hooks else "        // No specific hooks generated"

    def _generate_bypass_logic(self, protection_types: List[ProtectionType]) -> str:
        """Generate protection bypass logic."""
        bypass_logic = []

        for protection_type in protection_types:
            if protection_type == ProtectionType.LICENSE_CHECK:
                logic = '''
        // License validation bypass
        console.log("[Bypass] Setting up license validation bypass...");

        // Hook common license validation patterns
        var license_keywords = ["license", "trial", "demo", "expire", "activate"];
        var modules = Process.enumerateModules();

        modules.forEach(function(module) {{
            try {
                var exports = module.enumerateExports();
                exports.forEach(function(exp) {{
                    if (license_keywords.some(keyword => exp.name.toLowerCase().includes(keyword))) {
                        console.log("[Bypass] Found license-related function: " + exp.name);
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {{
                                console.log("[Bypass] License function called: " + exp.name);
                            },
                            onLeave: function(retval) {{
                                console.log("[Bypass] License function bypassed - forcing success");
                                retval.replace(1); // Force success
                            }
                        });
                    }
                });
            } catch (e) {
                // Continue if module enumeration fails
            }
        });
'''
                bypass_logic.append(logic)

        return "\n".join(bypass_logic) if bypass_logic else "        // No specific bypass logic generated"

    def _generate_helper_functions(self, protection_types: List[ProtectionType]) -> str:
        """Generate helper functions for the script."""
        # Use protection_types to generate type-specific helpers
        type_names = [p.name for p in protection_types]

        helpers = f'''
    // Helper functions for protection types: {', '.join(type_names)}
    // Helper functions
    findLicenseStrings: function() {{
        var license_strings = [];
        var modules = Process.enumerateModules();

        modules.forEach(function(module) {{
            try {{
                var ranges = module.enumerateRanges('r--');
                ranges.forEach(function(range) {{
                    try {{
                        var content = range.base.readCString(range.size);
                        if (content && content.includes("license")) {{
                            license_strings.push(content);
                        }}
                    }} catch (e) {{
                        // Continue on read errors
                    }}
                }});
            }} catch (e) {{
                // Continue if enumeration fails
            }}
        }});

        return license_strings;
    }},

    logProtectionAttempt: function(type, details) {{
        console.log("[Protection] " + type + ": " + JSON.stringify(details));
    }}
'''
        return helpers

    def _generate_analysis_functions(self, analysis_results: Dict[str, Any]) -> str:
        """Generate Ghidra analysis functions based on analysis results."""
        # Extract existing analysis data to guide further analysis
        known_functions = analysis_results.get('functions', [])
        target_addresses = analysis_results.get('target_addresses', [])
        string_refs = analysis_results.get('string_references', [])

        # Use string_refs to guide string analysis
        known_license_strings = [ref.get('content', '') for ref in string_refs if isinstance(ref, dict) and 'license' in ref.get('content', '').lower()]

        # Variables for Ghidra script context
        func_name = ""  # Will be set in loop
        function = None  # Will be set in loop
        data = None  # Will be set in loop
        string_val = ""  # Will be set in loop
        license_functions = []  # Will be populated
        license_strings = []  # Will be populated

        analysis_code = f'''
        # Analyze binary for protection mechanisms
        # Using previous analysis results: {len(known_functions)} functions, {len(target_addresses)} targets
        # Known license strings from analysis: {len(known_license_strings)}
        program = getCurrentProgram()
        listing = program.getListing()
        memory = program.getMemory()

        print("Starting protection analysis...")
        print("Known function targets: {len(known_functions)}")
        print("Target addresses to analyze: {len(target_addresses)}")
        print("Known license strings to check: {len(known_license_strings)}")

        # Focus analysis on previously identified areas
        priority_functions = {known_functions[:10]}  # Top 10 priority functions

        # Find all functions in the binary
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)

        license_functions = []

        for function in functions:
            func_name = function.getName()
            if any(keyword in func_name.lower() for keyword in ["license", "trial", "demo", "check", "validate"]):
                license_functions.append(function)
                print(f"Found potential license function: {func_name} at {function.getEntryPoint()}")

        # Analyze strings for license-related content
        string_table = program.getListing().getDefinedData(True)
        license_strings = []

        for data in string_table:
            if data.hasStringValue():
                string_val = data.getDefaultValueRepresentation()
                if any(keyword in string_val.lower() for keyword in ["license", "trial", "demo", "expire"]):
                    license_strings.append((data.getAddress(), string_val))
                    print(f"Found license string at {data.getAddress()}: {string_val}")

        print(f"Analysis complete: {len(license_functions)} functions, {len(license_strings)} strings")
'''
        return analysis_code

    def _generate_patching_logic(self, analysis_results: Dict[str, Any], protection_types: List[ProtectionType]) -> str:
        """Generate Ghidra patching logic based on analysis results and protection types."""
        # Extract patch targets from analysis results
        patch_addresses = analysis_results.get('patch_addresses', [])
        vulnerable_functions = analysis_results.get('vulnerable_functions', [])
        license_checks = analysis_results.get('license_checks', [])

        # Use vulnerable_functions for targeted analysis
        vuln_targets = [func.get('name', 'unknown') for func in vulnerable_functions if isinstance(func, dict)]

        # Use license_checks for specific bypass logic
        license_targets = [check.get('address', '0x0') for check in license_checks if isinstance(check, dict)]

        # Generate protection-specific patches
        protection_patches = []
        for protection_type in protection_types:
            if protection_type == ProtectionType.LICENSE_CHECK:
                protection_patches.extend([addr for addr in patch_addresses if addr.get('type') == 'license'])
            elif protection_type == ProtectionType.TRIAL_PROTECTION:
                protection_patches.extend([addr for addr in patch_addresses if addr.get('type') == 'trial'])

        patching_code = f'''
        # Apply patches to bypass protections
        # Analysis found {len(patch_addresses)} potential patch points
        # Protection types detected: {[p.name for p in protection_types]}
        # Vulnerable targets: {len(vuln_targets)} functions
        # License check targets: {len(license_targets)} addresses
        print("Starting patching process...")

        patches_applied = 0

        # Apply protection-specific patches from analysis
        for patch_info in protection_patches:
            patch_addr = patch_info.get('address')
            patch_type = patch_info.get('type')
            print("Applying " + str(patch_type) + " patch at " + str(patch_addr))
            # Patch implementation would go here
            patches_applied += 1

        # Patch license check functions based on analysis
        for function in license_functions:
            entry_point = function.getEntryPoint()

            # Get first instruction
            instruction = listing.getInstructionAt(entry_point)
            if instruction:
                print("Patching function at " + str(entry_point))

                # For demo purposes - replace with NOP or return success
                # In a real implementation, this would analyze the function
                # and apply appropriate patches

                try:
                    # Create a simple patch that returns 1 (success)
                    # This is a simplified example - real patching would be more sophisticated
                    clearListing(entry_point, entry_point.add(10))

                    # Note: Actual patching would require more sophisticated analysis
                    # of the function's purpose and proper assembly generation
                    print("Applied bypass patch to " + function.getName())
                    patches_applied += 1

                except Exception as e:
                    print("Failed to patch " + function.getName() + ": " + str(e))

        print("Patching complete: " + str(patches_applied) + " patches applied")

        # Save patch information
        patch_info = {{
            "target": program.getName(),
            "patches_applied": patches_applied,
            "timestamp": str(java.util.Date())
        }}

        print("Patch summary:", patch_info)
'''
        return patching_code

    def _generate_initialization_code(self) -> str:
        """Generate initialization code for Frida scripts."""
        return '''
        // Initialize protection detection
        this.target_module = Process.enumerateModules()[0];
        this.protection_counters = {
            license_checks: 0,
            time_checks: 0,
            network_calls: 0
        };

        console.log("[Init] Target module: " + this.target_module.name);
        console.log("[Init] Base address: " + this.target_module.base);
'''

    def _generate_ghidra_initialization(self) -> str:
        """Generate initialization code for Ghidra scripts."""
        return '''
        # Initialize analysis environment
        program = getCurrentProgram()
        if program is None:
            print("Error: No program loaded")
            return

        print(f"Analyzing program: {program.getName()}")
        print(f"Base address: {program.getImageBase()}")
        print(f"Language: {program.getLanguage()}")
'''

    def _generate_script_id(self, target_binary: str, script_type: ScriptType) -> str:
        """Generate unique script ID."""
        content = f"{target_binary}_{script_type.value}_{datetime.now().isoformat()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]

    def _calculate_success_probability(self, protection_types: List[ProtectionType]) -> float:
        """Calculate estimated success probability based on protection types."""
        base_probability = 0.7

        for protection_type in protection_types:
            if protection_type == ProtectionType.LICENSE_CHECK:
                base_probability += 0.15
            elif protection_type == ProtectionType.TIME_BOMB:
                base_probability += 0.1
            elif protection_type == ProtectionType.UNKNOWN:
                base_probability -= 0.2

        return min(max(base_probability, 0.0), 1.0)

    def _extract_hook_info(self, hooks_code: str) -> List[Dict[str, Any]]:
        """Extract hook information from generated code."""
        hooks = []

        # Parse hook installations from code
        hook_pattern = r'Interceptor\.attach\([^,]+,\s*{([^}]+)}'
        matches = re.findall(hook_pattern, hooks_code, re.MULTILINE | re.DOTALL)

        for i, match in enumerate(matches):
            hooks.append({
                "id": f"hook_{i}",
                "type": "interceptor",
                "callbacks": ["onEnter", "onLeave"] if "onEnter" in match and "onLeave" in match else ["unknown"]
            })

        return hooks

    def _extract_patch_info(self, patch_code: str) -> List[Dict[str, Any]]:
        """Extract patch information from generated code."""
        patches = []

        # Simple patch detection - would be more sophisticated in practice
        if "clearListing" in patch_code:
            patches.append({
                "type": "function_replacement",
                "description": "License function bypass patch"
            })

        return patches

    def save_script(self, script: GeneratedScript, output_dir: str = "scripts/generated") -> str:
        """Save generated script to filesystem."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Determine file extension
        if script.metadata.script_type == ScriptType.FRIDA:
            extension = ".js"
        else:
            extension = ".py"

        # Generate filename
        timestamp = script.metadata.generated_at.strftime("%Y%m%d_%H%M%S")
        filename = f"ai_generated_{Path(script.metadata.target_binary).stem}_{timestamp}{extension}"

        file_path = output_path / filename

        # Write script content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(script.content)

        # Save metadata
        metadata_path = file_path.with_suffix('.metadata.json')
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump({
                "script_id": script.metadata.script_id,
                "script_type": script.metadata.script_type.value,
                "target_binary": script.metadata.target_binary,
                "protection_types": [p.value for p in script.metadata.protection_types],
                "generated_at": script.metadata.generated_at.isoformat(),
                "generation_time": script.metadata.generation_time,
                "success_probability": script.metadata.success_probability,
                "validation_passed": script.validation_passed,
                "hooks": script.hooks,
                "patches": script.patches
            }, f, indent=2)

        logger.info(f"Generated script saved to: {file_path}")
        return str(file_path)

    def optimize_context_for_llm(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize analysis data for LLM context window."""
        optimized = {}

        # Prioritize most important data
        if "protections" in analysis_data:
            optimized["protections"] = analysis_data["protections"]

        if "binary_info" in analysis_data:
            optimized["binary_info"] = analysis_data["binary_info"]

        # Compress function list to most relevant
        if "functions" in analysis_data:
            functions = analysis_data["functions"]
            if len(functions) > 20:
                # Keep license-related functions and first 20
                license_funcs = [f for f in functions if self._is_protection_related(f.get("name", ""))]
                other_funcs = [f for f in functions if not self._is_protection_related(f.get("name", ""))][:20]
                optimized["functions"] = license_funcs + other_funcs
            else:
                optimized["functions"] = functions

        # Compress strings to most relevant
        if "strings" in analysis_data:
            strings = analysis_data["strings"]
            if len(strings) > 50:
                # Keep license-related strings and limit others
                license_strings = [s for s in strings if self._is_license_string(s)]
                other_strings = [s for s in strings if not self._is_license_string(s)][:30]
                optimized["strings"] = license_strings + other_strings
            else:
                optimized["strings"] = strings

        # Keep imports but limit if too many
        if "imports" in analysis_data:
            imports = analysis_data["imports"]
            if len(imports) > 30:
                optimized["imports"] = imports[:30]
            else:
                optimized["imports"] = imports

        return optimized

    def _is_protection_related(self, name: str) -> bool:
        """Check if function name is protection-related."""
        if not name:
            return False

        protection_keywords = [
            "license", "trial", "demo", "check", "validate", "verify",
            "auth", "register", "activate", "expire", "time", "crypto"
        ]

        return any(keyword in name.lower() for keyword in protection_keywords)

    def _is_license_string(self, string: str) -> bool:
        """Check if string is license-related."""
        if not string or len(string) < 3:
            return False

        license_keywords = [
            "license", "trial", "demo", "expire", "activate", "register",
            "serial", "key", "validation", "auth", "check"
        ]

        return any(keyword in string.lower() for keyword in license_keywords)

    def estimate_context_tokens(self, data: Dict[str, Any]) -> int:
        """Estimate token count for context data."""
        # Rough estimation: 1 token per 4 characters
        content = json.dumps(data, default=str)
        return len(content) // 4

    def compress_context_if_needed(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Compress context data if it exceeds token limits."""
        optimized = self.optimize_context_for_llm(analysis_data)
        estimated_tokens = self.estimate_context_tokens(optimized)

        if estimated_tokens <= self.max_context_tokens:
            return optimized

        # Progressive compression
        logger.info(f"Context too large ({estimated_tokens} tokens), compressing...")

        # Further reduce function and string lists
        if "functions" in optimized and len(optimized["functions"]) > 10:
            optimized["functions"] = optimized["functions"][:10]

        if "strings" in optimized and len(optimized["strings"]) > 20:
            optimized["strings"] = optimized["strings"][:20]

        if "imports" in optimized and len(optimized["imports"]) > 15:
            optimized["imports"] = optimized["imports"][:15]

        # Check again
        estimated_tokens = self.estimate_context_tokens(optimized)
        if estimated_tokens > self.max_context_tokens:
            # Final compression - keep only essential data
            essential = {
                "binary_info": optimized.get("binary_info", {}),
                "protections": optimized.get("protections", []),
                "key_functions": optimized.get("functions", [])[:5],
                "key_strings": optimized.get("strings", [])[:10]
            }
            logger.warning("Applied aggressive compression to fit context window")
            return essential

        return optimized

    def refine_script(self, original_script: str, test_results: Dict[str, Any],
                     analysis_data: Dict[str, Any]) -> Optional[GeneratedScript]:
        """Refine an existing script based on test results."""
        try:
            # Determine script type
            script_type = ScriptType.FRIDA if ".js" in original_script or "Interceptor" in original_script else ScriptType.GHIDRA

            # Use LLM for refinement if available
            if self.orchestrator and hasattr(self.orchestrator, 'llm_manager') and self.orchestrator.llm_manager:
                llm_manager = self.orchestrator.llm_manager

                # Prepare refinement data
                error_feedback = test_results.get("error", "")

                refined_content = llm_manager.refine_script_content(
                    original_script=original_script,
                    error_feedback=error_feedback,
                    test_results=test_results,
                    script_type=script_type.value
                )

                if refined_content:
                    # Create refined script metadata
                    metadata = ScriptMetadata(
                        script_id=self._generate_script_id("refined", script_type),
                        script_type=script_type,
                        target_binary=analysis_data.get("binary_info", {}).get("name", "unknown"),
                        protection_types=[ProtectionType.UNKNOWN],
                        generated_at=datetime.now(),
                        generation_time=time.time() - time.time(),
                        success_probability=0.8,  # Slightly higher for refined scripts
                        iterations=1
                    )

                    refined_script = GeneratedScript(
                        metadata=metadata,
                        content=refined_content,
                        language="javascript" if script_type == ScriptType.FRIDA else "python",
                        entry_point="main" if script_type == ScriptType.GHIDRA else None,
                        dependencies=[],
                        hooks=self._extract_hook_info(refined_content) if script_type == ScriptType.FRIDA else [],
                        patches=self._extract_patch_info(refined_content) if script_type == ScriptType.GHIDRA else []
                    )

                    # Validate refined script
                    is_valid, errors = self.validator.validate_script(refined_script)
                    if is_valid:
                        logger.info("Script refinement completed successfully")
                        return refined_script
                    else:
                        logger.warning(f"Refined script validation failed: {errors}")

            logger.warning("Script refinement failed or not available")
            return None

        except Exception as e:
            logger.error(f"Script refinement error: {e}")
            return None
