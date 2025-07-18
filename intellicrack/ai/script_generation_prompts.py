
"""
Specialized Prompts for AI Script Generation

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

import logging
from enum import Enum
from typing import Any, Dict, List


class PromptType(Enum):
    """Types of prompts for script generation."""
    FRIDA_BASIC = "frida_basic"
    FRIDA_ADVANCED = "frida_advanced"
    GHIDRA_BASIC = "ghidra_basic"
    GHIDRA_ADVANCED = "ghidra_advanced"
    ANALYSIS = "analysis"
    REFINEMENT = "refinement"
    VALIDATION = "validation"


class ScriptGenerationPrompts:
    """
    Comprehensive prompt library for AI script generation.
    All prompts enforce zero placeholder policy.
    """

    def __init__(self):
        """Initialize the script generation prompts manager.
        
        Sets up prompts for various script generation tasks including
        Frida, Ghidra, and other dynamic analysis tools.
        """
        self.logger = logging.getLogger(__name__ + ".ScriptGenerationPrompts")
        self.prompts = self._initialize_prompts()

    def _initialize_prompts(self) -> Dict[PromptType, Dict[str, str]]:
        """Initialize all prompt templates."""
        return {
            PromptType.FRIDA_BASIC: {
                "system": """You are an autonomous Frida JavaScript expert for binary reverse engineering and protection bypass.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional Frida JavaScript code
- NO placeholders, stubs, TODOs, or incomplete functions
- Every Interceptor.attach() must have complete onEnter and onLeave implementations
- All API calls must be correct Frida API usage
- Scripts must be production-ready and immediately executable
- Use proper error handling with try/catch blocks
- Include comprehensive logging for debugging

Your expertise covers:
- Function hooking and interception
- Memory manipulation
- API monitoring
- Protection bypass techniques
- Real-time binary analysis

Generate complete, working Frida scripts only.""",

                "user_template": """Target Binary: {binary_name}
Protection Types: {protection_types}
Analysis Data: {analysis_summary}

Required Script Functionality:
{functionality_requirements}

Binary Details:
- Architecture: {architecture}
- Platform: {platform}
- Key Functions: {key_functions}
- Import Table: {imports}
- Detected Strings: {license_strings}

Generate a complete Frida JavaScript script that:
1. Hooks all relevant protection functions
2. Bypasses the identified protection mechanisms
3. Provides detailed logging of all intercepted calls
4. Handles errors gracefully
5. Is immediately ready for execution

Return ONLY the complete Frida script code."""
            },

            PromptType.FRIDA_ADVANCED: {
                "system": """You are an autonomous senior Frida expert specializing in complex protection bypass and advanced hooking techniques.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional Frida JavaScript code
- NO placeholders, stubs, TODOs, or incomplete functions
- Implement advanced techniques: memory scanning, dynamic patching, multi-layer hooks
- Handle complex protection schemes: anti-debugging, VM detection, crypto validation
- Use advanced Frida APIs: Memory, Module, Process, NativeFunction
- Include performance optimizations and resource management
- Implement sophisticated bypass strategies

Advanced capabilities to utilize:
- Memory scanning and pattern matching
- Dynamic code patching and replacement
- Multi-stage hooking strategies  
- Process and module enumeration
- Advanced debugging evasion
- Cryptographic function replacement

Generate production-grade Frida scripts with advanced techniques.""",

                "user_template": """Target Binary: {binary_name}
Complex Protection Analysis:
{detailed_analysis}

Advanced Requirements:
{advanced_requirements}

Detected Protection Layers:
{protection_layers}

Memory Layout Information:
{memory_info}

Anti-Analysis Mechanisms:
{anti_analysis}

Generate an advanced Frida script that:
1. Implements multi-layer protection bypass
2. Uses advanced memory manipulation techniques
3. Handles complex anti-debugging measures
4. Employs sophisticated hooking strategies
5. Includes performance monitoring and optimization
6. Is resilient against detection and counter-measures

Return ONLY the complete advanced Frida script code."""
            },

            PromptType.GHIDRA_BASIC: {
                "system": """You are an autonomous Ghidra Python expert for automated binary analysis and patching.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional Ghidra Python code
- NO placeholders, stubs, TODOs, or incomplete functions
- Use correct Ghidra API calls and proper syntax
- Include proper error handling and validation
- Scripts must work with headless Ghidra analysis
- Implement complete analysis and patching workflows
- Use proper Ghidra data types and structures

Your expertise includes:
- Binary analysis automation
- Function identification and analysis
- Memory patching and modification
- Cross-reference analysis
- String and constant analysis
- Control flow analysis

Generate complete, working Ghidra Python scripts only.""",

                "user_template": """Target Binary: {binary_name}
Analysis Requirements: {analysis_requirements}
Protection Information: {protection_info}

Binary Characteristics:
- File Type: {file_type}
- Architecture: {architecture}
- Entry Point: {entry_point}
- Key Addresses: {key_addresses}
- Protection Functions: {protection_functions}

Patching Objectives:
{patching_objectives}

Generate a complete Ghidra Python script that:
1. Performs automated analysis of the target binary
2. Identifies protection mechanisms and key functions
3. Applies necessary patches to bypass protections
4. Validates the patches are applied correctly
5. Generates a comprehensive analysis report
6. Is ready for headless execution

Return ONLY the complete Ghidra Python script code."""
            },

            PromptType.GHIDRA_ADVANCED: {
                "system": """You are a senior Ghidra developer specializing in complex binary analysis, advanced patching, and automated reverse engineering workflows.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional Ghidra Python code
- NO placeholders, stubs, TODOs, or incomplete functions
- Implement advanced analysis algorithms and techniques
- Use sophisticated Ghidra APIs: Program Database, Function Manager, Symbol Table
- Handle complex binary structures and obfuscation
- Implement intelligent patching strategies with safety checks
- Include comprehensive validation and verification

Advanced capabilities to implement:
- Control flow graph analysis
- Data flow tracking and analysis
- Advanced decompilation integration
- Intelligent symbol resolution
- Cross-reference pattern analysis
- Automated vulnerability discovery
- Complex patching with safety verification

Generate enterprise-grade Ghidra automation scripts.""",

                "user_template": """Target Binary: {binary_name}
Complex Analysis Requirements:
{complex_analysis}

Advanced Objectives:
{advanced_objectives}

Binary Complexity Factors:
{complexity_factors}

Obfuscation Analysis:
{obfuscation_info}

Critical Functions Analysis:
{critical_functions}

Generate an advanced Ghidra Python script that:
1. Performs deep structural analysis of the binary
2. Handles complex obfuscation and protection schemes
3. Implements intelligent patching with safety verification
4. Uses advanced analysis algorithms for pattern detection
5. Integrates with Ghidra's decompiler for semantic analysis
6. Provides comprehensive reporting and validation
7. Is robust against analysis-resistant binaries

Return ONLY the complete advanced Ghidra Python script code."""
            },

            PromptType.ANALYSIS: {
                "system": """You are an autonomous binary protection expert specializing in identifying and categorizing protection mechanisms.

Analyze binary data and identify:
- License validation schemes
- Trial timer implementations  
- Network-based validations
- Anti-debugging techniques
- VM detection methods
- Cryptographic protections
- Obfuscation techniques

Provide detailed analysis with actionable bypass strategies.""",

                "user_template": """Binary Analysis Data:
{binary_data}

Provide comprehensive protection analysis including:
1. Identified protection mechanisms with confidence levels
2. Specific bypass strategies for each protection
3. Risk assessment and complexity analysis
4. Recommended tools and techniques
5. Priority order for bypass implementation

Return analysis in structured JSON format."""
            },

            PromptType.REFINEMENT: {
                "system": """You are an autonomous script debugging and optimization expert.

CRITICAL REQUIREMENTS:
- Generate ONLY real, functional code improvements
- NO placeholders, stubs, TODOs, or incomplete fixes
- Fix all identified errors and issues
- Improve script reliability and robustness
- Maintain original functionality while enhancing performance
- Add proper error handling and edge case management

Your task is to refine and improve existing scripts based on test results and feedback.""",

                "user_template": """Original Script:
{original_script}

Test Results:
{test_results}

Error Feedback:
{error_feedback}

Performance Issues:
{performance_issues}

Provide a complete refined script that:
1. Fixes all identified errors and issues
2. Improves reliability and error handling
3. Enhances performance and efficiency
4. Maintains original functionality
5. Adds better logging and debugging support
6. Is production-ready and thoroughly tested

Return ONLY the complete refined script code."""
            },

            PromptType.VALIDATION: {
                "system": """You are a code validation specialist for Frida and Ghidra scripts.

Analyze scripts for:
- Syntax errors and API misuse
- Logic errors and edge cases
- Security vulnerabilities
- Performance issues
- Best practice violations
- Compatibility problems

Provide detailed validation results with specific recommendations.""",

                "user_template": """Script Type: {script_type}
Script Content:
{script_content}

Validation Requirements:
{validation_requirements}

Provide comprehensive validation analysis:
1. Syntax and API usage validation
2. Logic error detection
3. Security vulnerability assessment
4. Performance optimization opportunities
5. Best practice recommendations
6. Compatibility and reliability checks

Return validation results in structured JSON format."""
            }
        }

    def get_prompt(self, prompt_type: PromptType, **kwargs) -> Dict[str, str]:
        """Get formatted prompt for specific type."""
        if prompt_type not in self.prompts:
            raise ValueError(f"Unknown prompt type: {prompt_type}")

        prompt_data = self.prompts[prompt_type].copy()

        # Format user template if provided
        if "user_template" in prompt_data and kwargs:
            try:
                prompt_data["user_template"] = prompt_data["user_template"].format(
                    **kwargs)
            except KeyError as e:
                self.logger.error(
                    "Key error in script_generation_prompts: %s", e)
                # If a required key is missing, return the template with placeholders
                # This allows the caller to see what keys are needed
                pass

        return prompt_data

    def get_frida_prompt(self, complexity: str = "basic", **kwargs) -> Dict[str, str]:
        """Get Frida-specific prompt."""
        prompt_type = PromptType.FRIDA_ADVANCED if complexity == "advanced" else PromptType.FRIDA_BASIC
        return self.get_prompt(prompt_type, **kwargs)

    def get_ghidra_prompt(self, complexity: str = "basic", **kwargs) -> Dict[str, str]:
        """Get Ghidra-specific prompt."""
        prompt_type = PromptType.GHIDRA_ADVANCED if complexity == "advanced" else PromptType.GHIDRA_BASIC
        return self.get_prompt(prompt_type, **kwargs)

    def build_context_data(self, binary_analysis: Dict[str, Any],
                           protection_types: List[str] = None) -> Dict[str, str]:
        """Build context data for prompt formatting."""
        context = {
            "binary_name": binary_analysis.get("binary_info", {}).get("name", "unknown"),
            "architecture": binary_analysis.get("binary_info", {}).get("arch", "x64"),
            "platform": binary_analysis.get("binary_info", {}).get("platform", "windows"),
            "file_type": binary_analysis.get("binary_info", {}).get("type", "PE"),
            "entry_point": "0x401000",  # Default
            "protection_types": ", ".join(protection_types or ["license_check"]),
            "key_functions": ", ".join([f["name"] for f in binary_analysis.get("functions", [])[:10]]),
            "imports": ", ".join(binary_analysis.get("imports", [])[:15]),
            "license_strings": ", ".join([s for s in binary_analysis.get("strings", [])
                                          if any(keyword in s.lower() for keyword in
                                                 ["license", "trial", "demo", "expire"])]),
            "analysis_summary": self._summarize_analysis(binary_analysis),
            "functionality_requirements": self._build_functionality_requirements(protection_types or []),
            # Example addresses
            "key_addresses": ", ".join(["0x401000", "0x401200", "0x401400"]),
            "protection_functions": ", ".join([f["name"] for f in binary_analysis.get("functions", [])
                                               if "license" in f.get("name", "").lower() or
                                               "check" in f.get("name", "").lower()]),
            "patching_objectives": self._build_patching_objectives(protection_types or [])
        }

        return context

    def _summarize_analysis(self, analysis: Dict[str, Any]) -> str:
        """Create a summary of binary analysis."""
        protections = analysis.get("protections", [])
        summary_parts = []

        for protection in protections:
            ptype = protection.get("type", "unknown")
            confidence = protection.get("confidence", 0.0)
            summary_parts.append(f"{ptype} (confidence: {confidence:.1%})")

        if not summary_parts:
            return "Basic binary analysis completed, no specific protections detected."

        return f"Detected protections: {', '.join(summary_parts)}"

    def _build_functionality_requirements(self, protection_types: List[str]) -> str:
        """Build functionality requirements based on protection types."""
        requirements = []

        for ptype in protection_types:
            if "license" in ptype.lower():
                requirements.append(
                    "- Hook license validation functions and force success")
                requirements.append(
                    "- Monitor registry/file access for license storage")
                requirements.append("- Bypass string comparison checks")
            elif "trial" in ptype.lower() or "time" in ptype.lower():
                requirements.append(
                    "- Hook time-related functions (GetSystemTime, etc.)")
                requirements.append(
                    "- Manipulate time values to prevent expiration")
                requirements.append("- Monitor trial timer mechanisms")
            elif "network" in ptype.lower():
                requirements.append("- Intercept network validation calls")
                requirements.append("- Provide fake license server responses")
                requirements.append("- Block outbound license verification")
            elif "debug" in ptype.lower():
                requirements.append("- Bypass debugger detection mechanisms")
                requirements.append(
                    "- Hook IsDebuggerPresent and related functions")
                requirements.append(
                    "- Manipulate PEB flags and debug registers")

        if not requirements:
            requirements = [
                "- Analyze binary for protection mechanisms",
                "- Hook suspicious functions for monitoring",
                "- Implement generic bypass strategies"
            ]

        return "\n".join(requirements)

    def _build_patching_objectives(self, protection_types: List[str]) -> str:
        """Build patching objectives for Ghidra scripts."""
        objectives = []

        for ptype in protection_types:
            if "license" in ptype.lower():
                objectives.append(
                    "- Patch license check jumps to always succeed")
                objectives.append(
                    "- Modify string comparisons to return equal")
                objectives.append(
                    "- Replace license validation with NOP instructions")
            elif "trial" in ptype.lower():
                objectives.append("- Patch time check comparisons")
                objectives.append("- Modify trial expiration logic")
                objectives.append(
                    "- Replace time-based jumps with unconditional success")
            elif "network" in ptype.lower():
                objectives.append("- Patch network calls to return success")
                objectives.append("- Modify validation responses")
                objectives.append("- Bypass online license requirements")

        if not objectives:
            objectives = [
                "- Identify and patch protection mechanisms",
                "- Modify conditional jumps for bypass",
                "- Apply safety-verified binary patches"
            ]

        return "\n".join(objectives)

    def get_available_prompt_types(self) -> List[str]:
        """Get list of available prompt types."""
        return [pt.value for pt in PromptType]

    def get_prompt_requirements(self, prompt_type: PromptType) -> List[str]:
        """Get required parameters for a prompt type."""
        if prompt_type not in self.prompts:
            return []

        template = self.prompts[prompt_type].get("user_template", "")

        # Extract format placeholders
        import re
        placeholders = re.findall(r'\{(\w+)\}', template)
        return list(set(placeholders))


# Global prompt manager instance
_PROMPT_MANAGER = None


def get_prompt_manager() -> ScriptGenerationPrompts:
    """Get the global prompt manager instance."""
    global _PROMPT_MANAGER
    if _PROMPT_MANAGER is None:
        _PROMPT_MANAGER = ScriptGenerationPrompts()
    return _PROMPT_MANAGER
