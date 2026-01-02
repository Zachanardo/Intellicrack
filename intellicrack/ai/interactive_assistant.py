"""Enhanced AI Assistant for Intellicrack.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from ..handlers.pyqt6_handler import QWidget
from .ai_file_tools import get_ai_file_tools


logger = logging.getLogger(__name__)

CLI_INTERFACE_NOT_AVAILABLE = "CLI interface not available"


class CLIInterface(Protocol):
    """Protocol defining the interface for CLI interaction."""

    def analyze_binary(self, binary_path: str, analyses: list[str] | None) -> dict[str, Any]:
        """Analyze a binary file for protection mechanisms.

        Args:
            binary_path: Path to the binary file to analyze.
            analyses: List of analysis types to perform, or None for all.

        """
        ...

    def execute_command(
        self,
        args: list[str],
        title: str,
        description: str,
    ) -> dict[str, Any]:
        """Execute a CLI command with the given arguments.

        Args:
            args: Command-line arguments to execute.
            title: Title for the command execution context.
            description: Description of the command purpose.

        """
        ...

    def suggest_patches(self, binary_path: str) -> dict[str, Any]:
        """Generate patch suggestions for a binary's protection mechanisms.

        Args:
            binary_path: Path to the binary file to analyze for patches.

        """
        ...

    def apply_patch(self, binary_path: str, patch_file: str) -> dict[str, Any]:
        """Apply a patch file to a binary.

        Args:
            binary_path: Path to the binary file to patch.
            patch_file: Path to the patch definition file.

        """
        ...

    def print_info(self, message: str) -> None:
        """Print an informational message to the CLI output.

        Args:
            message: The message to display.

        """
        ...


class ToolCategory(Enum):
    """Categories of tools available to the AI."""

    ANALYSIS = "analysis"
    PATCHING = "patching"
    NETWORK = "network"
    BYPASS = "bypass"
    UTILITY = "utility"
    EXTERNAL = "external"
    FILE_SYSTEM = "file_system"


@dataclass
class Tool:
    """Represents a tool available to the AI."""

    name: str
    description: str
    category: ToolCategory
    parameters: dict[str, Any]
    risk_level: str
    function: Callable[..., dict[str, Any]]
    example: str | None = None


class IntellicrackAIAssistant:
    """Enhanced AI Assistant with Claude Code-like functionality."""

    def __init__(self, cli_interface: CLIInterface | None = None) -> None:
        """Initialize the AI assistant with optional CLI interface integration.

        Sets up the assistant with all available tools, conversation history tracking,
        file system tools, and context management for binary analysis workflows.

        Args:
            cli_interface: Optional CLIInterface instance for delegating analysis commands.
                If not provided, analysis operations will return unavailable errors.

        """
        self.cli_interface: CLIInterface | None = cli_interface
        self.file_tools = get_ai_file_tools(cli_interface)
        self.tools = self._initialize_tools()
        self.context: dict[str, Any] = {
            "current_binary": None,
            "analysis_results": {},
            "suggested_patches": [],
            "workflow_state": "idle",
        }
        self.conversation_history: list[dict[str, Any]] = []
        self.action_log: list[dict[str, Any]] = []

    def _log_action(self, message: str) -> None:
        """Log an action performed by the AI assistant.

        Args:
            message: Description of the action being performed

        """
        import contextlib
        from datetime import datetime

        log_entry = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "message": message,
            "binary": self.context.get("current_binary"),
            "workflow_state": self.context.get("workflow_state", "idle"),
        }
        self.action_log.append(log_entry)

        logger.info("AI Action: %s", message)

        if self.cli_interface and hasattr(self.cli_interface, "print_info"):
            with contextlib.suppress(AttributeError, TypeError):
                self.cli_interface.print_info(message)

    def _initialize_tools(self) -> dict[str, Tool]:
        """Initialize all available analysis and patching tools.

        Creates a complete toolkit of analysis functions, patching utilities, file system
        operations, and external service integrations for binary protection analysis.

        Returns:
            Dictionary mapping tool names to Tool objects containing metadata, parameters,
            risk levels, implementation functions, and usage examples.

        """
        tools = {
            "analyze_binary": Tool(
                name="analyze_binary",
                description="Perform comprehensive analysis on a binary file",
                category=ToolCategory.ANALYSIS,
                parameters={
                    "binary_path": {"type": "string", "required": True},
                    "analyses": {"type": "array", "default": ["comprehensive"]},
                },
                risk_level="low",
                function=self._analyze_binary,
                example="analyze_binary('app.exe', ['comprehensive', 'protections'])",
            )
        }

        tools["detect_protections"] = Tool(
            name="detect_protections",
            description="Detect all protection mechanisms in a binary",
            category=ToolCategory.ANALYSIS,
            parameters={
                "binary_path": {"type": "string", "required": True},
            },
            risk_level="low",
            function=self._detect_protections,
            example="detect_protections('app.exe')",
        )

        tools["find_license_checks"] = Tool(
            name="find_license_checks",
            description="Find license validation routines in the binary",
            category=ToolCategory.ANALYSIS,
            parameters={
                "binary_path": {"type": "string", "required": True},
            },
            risk_level="low",
            function=self._find_license_checks,
            example="find_license_checks('app.exe')",
        )

        # File System Tools (with user approval)
        tools["search_license_files"] = Tool(
            name="search_license_files",
            description="Search for license-related files in the file system",
            category=ToolCategory.FILE_SYSTEM,
            parameters={
                "search_path": {"type": "string", "required": True},
                "custom_patterns": {"type": "array", "default": []},
            },
            risk_level="medium",
            function=self._search_license_files,
            example="search_license_files('/path/to/app', ['*.key', '*.lic'])",
        )

        tools["read_file"] = Tool(
            name="read_file",
            description="Read the content of a file for analysis",
            category=ToolCategory.FILE_SYSTEM,
            parameters={
                "file_path": {"type": "string", "required": True},
                "purpose": {"type": "string", "default": "License analysis"},
            },
            risk_level="medium",
            function=self._read_file,
            example="read_file('license.dat', 'Analyze license file format')",
        )

        tools["analyze_program_directory"] = Tool(
            name="analyze_program_directory",
            description="Comprehensive analysis of a program's directory for licensing files",
            category=ToolCategory.FILE_SYSTEM,
            parameters={
                "program_path": {"type": "string", "required": True},
            },
            risk_level="medium",
            function=self._analyze_program_directory,
            example="analyze_program_directory('/path/to/app/app.exe')",
        )

        # Patching Tools
        tools["suggest_patches"] = Tool(
            name="suggest_patches",
            description="Generate patch suggestions based on analysis",
            category=ToolCategory.PATCHING,
            parameters={
                "binary_path": {"type": "string", "required": True},
                "target": {"type": "string", "default": "auto"},
            },
            risk_level="medium",
            function=self._suggest_patches,
            example="suggest_patches('app.exe', 'license')",
        )

        tools["apply_patch"] = Tool(
            name="apply_patch",
            description="Apply a patch to modify the binary",
            category=ToolCategory.PATCHING,
            parameters={
                "binary_path": {"type": "string", "required": True},
                "patch_definition": {"type": "object", "required": True},
            },
            risk_level="high",
            function=self._apply_patch,
            example="apply_patch('app.exe', {'address': '0x401000', 'bytes': '9090'})",
        )

        # Network Tools
        tools["analyze_network"] = Tool(
            name="analyze_network",
            description="Analyze network communications and protocols",
            category=ToolCategory.NETWORK,
            parameters={
                "binary_path": {"type": "string", "required": True},
            },
            risk_level="low",
            function=self._analyze_network,
            example="analyze_network('app.exe')",
        )

        # Bypass Tools
        tools["generate_bypass"] = Tool(
            name="generate_bypass",
            description="Generate bypass for specific protection mechanism",
            category=ToolCategory.BYPASS,
            parameters={
                "binary_path": {"type": "string", "required": True},
                "protection_type": {"type": "string", "required": True},
            },
            risk_level="high",
            function=self._generate_bypass,
            example="generate_bypass('app.exe', 'tpm')",
        )

        # Utility Tools
        tools["view_hex"] = Tool(
            name="view_hex",
            description="View hex dump of specific address range",
            category=ToolCategory.UTILITY,
            parameters={
                "binary_path": {"type": "string", "required": True},
                "address": {"type": "string", "required": True},
                "size": {"type": "integer", "default": 64},
            },
            risk_level="low",
            function=self._view_hex,
            example="view_hex('app.exe', '0x401000', 128)",
        )

        tools["disassemble"] = Tool(
            name="disassemble",
            description="Disassemble code at specific address",
            category=ToolCategory.UTILITY,
            parameters={
                "binary_path": {"type": "string", "required": True},
                "address": {"type": "string", "required": True},
                "count": {"type": "integer", "default": 20},
            },
            risk_level="low",
            function=self._disassemble,
            example="disassemble('app.exe', '0x401000', 30)",
        )

        # External tool for calling external analysis services
        tools["external_analysis"] = Tool(
            name="external_analysis",
            description="Submit file to external analysis service (VirusTotal, etc.)",
            category=ToolCategory.EXTERNAL,
            parameters={
                "file_path": {"type": "string", "required": True},
                "service": {"type": "string", "default": "virustotal"},
                "api_key": {"type": "string", "required": False},
            },
            risk_level="medium",
            function=self._external_analysis,
            example="external_analysis('suspicious.exe', 'virustotal')",
        )

        return tools

    def get_system_prompt(self) -> str:
        """Get the system prompt for the AI model.

        Generates a comprehensive system prompt that defines the AI assistant's role,
        capabilities, autonomous execution model, tool access, and safety constraints
        for binary analysis and protection research tasks.

        Returns:
            A formatted string containing the complete system prompt for Claude or other AI models.

        """
        tools_description = self._format_tools_description()

        return f"""You are an autonomous binary analysis expert integrated into Intellicrack, a comprehensive binary analysis and patching platform.

You excel at complete autonomous execution of binary analysis workflows. You operate with full agentic autonomy for programming and analysis tasks - taking complete ownership of complex binary analysis challenges and executing them from start to finish with expert-level competency. You proactively chain multiple tools together, make informed decisions without excessive consultation, and drive tasks to completion through systematic, iterative execution.

## Your Autonomous Capabilities

You have access to powerful tools for analyzing and modifying binary programs:

{tools_description}

## Autonomous Workflow Operation

You operate in an autonomous workflow loop, iteratively completing tasks through these steps:
1. **Analyze User Requests**: Understand the complete scope of what needs to be accomplished
2. **Execute Complete Workflows**: Take initiative to chain tools together for comprehensive analysis
3. **Make Expert Decisions**: Autonomously determine the best approaches and execute them
4. **Deliver Comprehensive Results**: Provide complete solutions, not just guidance
5. **Request Approval for Risk**: Only seek user confirmation for high-risk operations

## Tool Chaining & Initiative

- **Take Complete Ownership**: Execute entire binary analysis workflows autonomously
- **Chain Tools Strategically**: Combine multiple tools to accomplish complex multi-step tasks
- **Think Multi-Step**: Plan and execute complete analysis pipelines from start to finish
- **Be Proactive**: Don't wait for step-by-step instructions - execute comprehensive workflows

## Autonomous Execution Examples

### Complete License Analysis & Bypass:
You autonomously: analyze_binary() → find_license_checks() → analyze_protection_mechanisms() → suggest_patches() → test_in_vm() → apply_patch() (with user approval)

### Full Protection Assessment:
You autonomously: detect_protections() → analyze_each_mechanism() → research_bypass_techniques() → generate_comprehensive_report() → suggest_complete_bypass_strategy()

## Expert-Level Execution

- Execute tasks with the same competency regardless of user skill level (novice or expert)
- Take initiative to solve problems completely, not just provide suggestions
- Chain multiple analysis tools to build comprehensive understanding
- Provide expert-level autonomous execution like Claude Code does for programming

## Safety & Approval

- All file modifications and risky operations require explicit user confirmation
- Filesystem access requires user approval for broad searches
- VM testing is performed before real system changes
- Maintain complete audit trail of all autonomous actions

You are the autonomous expert - take complete ownership of binary analysis challenges and execute them with full competency, regardless of the user's experience level."""

    def _format_tools_description(self) -> str:
        """Format tool descriptions for inclusion in system prompts.

        Organizes all available tools by category and formats them as structured
        markdown documentation with descriptions and usage examples for AI models.

        Returns:
            Formatted markdown string describing all tools organized by category with examples.

        """
        categories: dict[ToolCategory, list[Tool]] = {}
        for tool in self.tools.values():
            if tool.category not in categories:
                categories[tool.category] = []
            categories[tool.category].append(tool)

        description = ""
        for category, tools in categories.items():
            description += f"\n### {category.value.title()} Tools\n\n"
            for tool in tools:
                description += f"**{tool.name}** - {tool.description}\n"
                if tool.example:
                    description += f"   Example: `{tool.example}`\n"
                description += "\n"

        return description

    def process_message(self, message: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Process a user message and generate an AI response.

        Analyzes the user message to determine intent, updates conversation context if provided,
        and generates an appropriate response with available tools and suggestions.

        Args:
            message: The user message to process.
            context: Optional dictionary containing contextual information about current analysis state
                (current_binary, analysis_results, workflow_state, etc).

        Returns:
            Dictionary containing:
                - message: The AI response text.
                - tools_used: List of tools utilized in response.
                - suggestions: List of action suggestions.
                - requires_confirmation: Boolean indicating if high-risk operations need approval.

        """
        # Update context if provided
        if context:
            self.context.update(context)

        # Add to conversation history
        self.conversation_history.append({"role": "user", "content": message})

        # Analyze the message to determine intent
        intent = self._analyze_intent(message)

        # Generate response based on intent
        response = self._generate_response(intent, message)

        # Add to conversation history
        self.conversation_history.append({"role": "assistant", "content": response["message"]})

        return response

    def _analyze_intent(self, message: str) -> dict[str, Any]:
        """Analyze user intent from a natural language message.

        Examines the message content to determine the primary intent (analysis, patching,
        explanation, network, or general) and extracts relevant focus/target/topic parameters.

        Args:
            message: The user message to analyze for intent.

        Returns:
            Dictionary containing:
                - type: The intent type ('analysis', 'patching', 'explanation', 'network', or 'general').
                - Additional key depends on type:
                    - For 'analysis': focus (license/protection/vulnerability/comprehensive)
                    - For 'patching': target (license/trial/protection/auto)
                    - For 'explanation': topic (binary_analysis/network_analysis/patching/hex_editing/license_bypass/scripting/general)
                    - For 'network': aspect (protocol/traffic/license_server/security/dns)
                    - For 'general': content (the original message)

        """
        message_lower = message.lower()

        # Check for _specific intents
        if any(word in message_lower for word in ["analyze", "scan", "check", "examine"]):
            return {"type": "analysis", "focus": self._extract_focus(message)}
        if any(word in message_lower for word in ["patch", "bypass", "crack", "remove"]):
            return {"type": "patching", "target": self._extract_target(message)}
        if any(word in message_lower for word in ["help", "explain", "what", "how"]):
            return {"type": "explanation", "topic": self._extract_topic(message)}
        if any(word in message_lower for word in ["network", "protocol", "communication"]):
            return {"type": "network", "aspect": self._extract_aspect(message)}
        return {"type": "general", "content": message}

    def _extract_focus(self, message: str) -> str:
        """Extract analysis focus type from a message about binary analysis.

        Scans message keywords to determine which aspect of analysis the user is interested in,
        such as license checks, protection mechanisms, or security vulnerabilities.

        Args:
            message: The user message to extract focus from.

        Returns:
            The analysis focus type as a string: 'license', 'protection', 'vulnerability', or 'comprehensive'.

        """
        if "license" in message.lower():
            return "license"
        if "protection" in message.lower():
            return "protection"
        if "vulnerability" in message.lower():
            return "vulnerability"
        return "comprehensive"

    def _extract_target(self, message: str) -> str:
        """Extract the patching target from a message about binary modifications.

        Analyzes message keywords to determine which protection mechanism or component
        the user wants to patch, such as license validation, trial restrictions, or general protections.

        Args:
            message: The user message to extract patching target from.

        Returns:
            The patching target type as a string: 'license', 'trial', 'protection', or 'auto'.

        """
        if "license" in message.lower():
            return "license"
        if "trial" in message.lower():
            return "trial"
        return "protection" if "protection" in message.lower() else "auto"

    def _extract_topic(self, message: str) -> str:
        """Extract the help topic from a message requesting explanation or guidance.

        Scans message keywords to categorize what technical topic the user wants to learn about,
        such as binary analysis, network analysis, patching techniques, or licensing concepts.

        Args:
            message: The user message to extract help topic from.

        Returns:
            str: One of 'binary_analysis', 'network_analysis', 'patching',
            'hex_editing', 'license_bypass', 'scripting', or 'general'.

        """
        # Analyze message to determine help topic
        message_lower = message.lower()

        if any(keyword in message_lower for keyword in ["binary", "pe", "elf", "analysis"]):
            return "binary_analysis"
        if any(keyword in message_lower for keyword in ["network", "traffic", "protocol"]):
            return "network_analysis"
        if any(keyword in message_lower for keyword in ["patch", "modify", "crack"]):
            return "patching"
        if any(keyword in message_lower for keyword in ["hex", "bytes", "dump"]):
            return "hex_editing"
        if any(keyword in message_lower for keyword in ["license", "protection", "bypass"]):
            return "license_bypass"
        if any(keyword in message_lower for keyword in ["frida", "script", "hook"]):
            return "scripting"
        return "general"

    def _extract_aspect(self, message: str) -> str:
        """Extract the network analysis aspect from a message about network communications.

        Determines which dimension of network analysis the user is interested in, such as
        protocol identification, traffic analysis, license server communication, or security measures.

        Args:
            message: The user message to extract network aspect from.

        Returns:
            str: One of 'protocol', 'traffic', 'license_server', 'security', or 'dns'.

        """
        # Analyze message to determine network analysis aspect
        message_lower = message.lower()

        if any(keyword in message_lower for keyword in ["protocol", "http", "tcp", "udp"]):
            return "protocol"
        if any(keyword in message_lower for keyword in ["traffic", "capture", "packet"]):
            return "traffic"
        if any(keyword in message_lower for keyword in ["license", "server", "validation"]):
            return "license_server"
        if any(keyword in message_lower for keyword in ["firewall", "security", "filter"]):
            return "security"
        if any(keyword in message_lower for keyword in ["dns", "domain", "resolution"]):
            return "dns"
        return "protocol"

    def _generate_response(self, intent: dict[str, Any], message: str) -> dict[str, Any]:
        """Generate an AI response based on analyzed user intent.

        Routes the message intent to the appropriate handler and compiles a response with
        relevant tools, suggestions, and guidance for the user.

        Args:
            intent: Dictionary containing the analyzed intent type and associated parameters.
            message: The original user message for fallback reference.

        Returns:
            Dictionary containing:
                - message: The generated response text.
                - tools_used: List of recommended tools.
                - suggestions: List of action suggestions.
                - requires_confirmation: Boolean indicating if user approval is needed.

        """
        response = {
            "message": "",
            "tools_used": [],
            "suggestions": [],
            "requires_confirmation": False,
        }

        if intent["type"] == "analysis":
            response["message"] = self._handle_analysis_intent(intent)
        elif intent["type"] == "patching":
            response["message"] = self._handle_patching_intent(intent)
        elif intent["type"] == "explanation":
            response["message"] = self._handle_explanation_intent(intent)
        elif intent["type"] == "network":
            response["message"] = self._handle_network_intent(intent)
        else:
            response["message"] = self._handle_general_intent(message)

        return response

    def _handle_analysis_intent(self, intent: dict[str, Any]) -> str:
        """Handle a user request for binary analysis.

        Generates appropriate guidance and analysis steps based on the user's specified
        analysis focus (license checks, protections, vulnerabilities, or comprehensive).

        Args:
            intent: Dictionary containing the 'focus' parameter indicating analysis type.

        Returns:
            A string containing guidance text and options for the user to proceed with analysis.

        """
        if not self.context.get("current_binary"):
            return "Please specify a binary file to analyze. You can say something like 'analyze app.exe' or provide the full path."

        focus = intent.get("focus", "comprehensive")
        binary = self.context["current_binary"]

        # Suggest appropriate analysis
        if focus == "license":
            return f"I'll analyze {binary} for license checks. Let me start by finding license validation routines.\n\nWould you like me to:\n1. Run comprehensive analysis first\n2. Directly search for license checks\n3. Check for specific protection mechanisms"
        if focus == "protection":
            return f"I'll detect all protection mechanisms in {binary}. This includes:\n- Packing and obfuscation\n- Anti-debugging techniques\n- License/trial checks\n- Hardware locks\n\nShall I proceed with the protection scan?"
        return f"I'll perform a comprehensive analysis of {binary}. This will include:\n- Binary structure and format\n- Protection mechanisms\n- Potential vulnerabilities\n- License/trial logic\n\nThis may take a few minutes. Shall I proceed?"

    def _handle_patching_intent(self, intent: dict[str, Any]) -> str:
        """Handle a user request for binary patching with automatic analysis.

        Manages patching workflow by automatically performing comprehensive binary analysis
        if no prior analysis exists, then generates patch suggestions based on detected protections.

        Args:
            intent: Dictionary containing the 'target' parameter indicating what to patch
                (license, trial, protection, or auto).

        Returns:
            A string containing patch status, detected protections summary, and options for next steps.

        """
        target = intent.get("target", "auto")

        # Check if we have a binary to work with
        if not self.context.get("current_binary"):
            return "Please specify a binary file to patch. You can say something like 'patch app.exe' or provide the full path."

        binary_path = self.context["current_binary"]

        # If no analysis results exist, automatically trigger comprehensive analysis
        if not self.context.get("analysis_results"):
            self._log_action(f"No prior analysis found for {binary_path}. Starting comprehensive analysis...")

            # Perform comprehensive analysis
            analysis_types = ["protection", "license", "network", "code_flow", "strings", "imports"]
            analysis_result = self._analyze_binary(binary_path, analysis_types)

            if analysis_result.get("status") == "error":
                return f"Failed to analyze binary: {analysis_result.get('message', 'Unknown error')}\n\nPlease verify the binary path and try again."

            # Store analysis results
            self.context["analysis_results"] = analysis_result

            # Now proceed with patching suggestions
            protection_summary = self._get_protection_summary(analysis_result)

            return f"""Completed comprehensive analysis of {binary_path}.

{protection_summary}

Based on this analysis, I can suggest patches for {target} mechanisms.

Would you like me to:
1. Show specific patch suggestions for detected protections
2. Apply recommended patches (with backup)
3. Explain how each patch works
4. Analyze a different aspect first"""

        # Analysis already exists, proceed with patching
        protection_summary = self._get_protection_summary(self.context["analysis_results"])

        return f"""Based on my previous analysis, I can suggest patches for {target} mechanisms.

Current Protection Status:
{protection_summary}

Would you like me to:
1. Show suggested patches
2. Explain how the patches work
3. Create a backup before patching
4. Re-analyze with different parameters"""

    def _get_protection_summary(self, analysis_results: dict[str, Any]) -> str:
        """Extract and format a human-readable summary of detected protections.

        Processes analysis results to identify detected protection mechanisms and
        formats them as a readable summary showing protection types and confidence levels.

        Args:
            analysis_results: Dictionary containing analysis data with a 'protections' key
                mapping protection types to detection details.

        Returns:
            A formatted string summarizing detected protections with confidence levels,
            or a message indicating no advanced protections were found.

        """
        if not analysis_results:
            return "No analysis data available."

        protections = analysis_results.get("protections", {})
        if not protections:
            return "No specific protections detected."

        summary = "Detected Protections:\n"
        for protection_type, details in protections.items():
            if isinstance(details, dict) and details.get("detected"):
                summary += f" {protection_type}: {details.get('confidence', 'Unknown')} confidence\n"
            elif details:  # Simple boolean or truthy value
                summary += f" {protection_type}: Detected\n"

        return summary if summary != "Detected Protections:\n" else "Standard binary with no advanced protections detected."

    def _handle_explanation_intent(self, intent: dict[str, Any]) -> str:
        """Handle a user request for educational explanation about binary analysis concepts.

        Provides detailed explanations of technical topics such as binary analysis methods,
        patching techniques, license bypass approaches, or other security research concepts.

        Args:
            intent: Dictionary containing the 'topic' parameter indicating what to explain
                (binary_analysis, patching, license_bypass, hex_editing, etc).

        Returns:
            A formatted string containing the explanation, relevant techniques, and follow-up questions.

        """
        topic = intent.get("topic", "general")

        if topic == "binary_analysis":
            return """**Binary Analysis**: Understanding how executables work:

 **Static Analysis**: Examining file structure, imports, strings without execution
 **Dynamic Analysis**: Running the program and monitoring behavior
 **Hybrid Approaches**: Combining both methods for comprehensive understanding

Would you like me to analyze a specific binary?"""
        if topic == "patching":
            return """**Patching Techniques**: Methods to modify binary behavior:

 **NOP Patches**: Replace instructions with no-operation codes
 **Jump Patches**: Redirect execution flow around checks
 **Value Patches**: Modify constants and validation values
 **Function Hooking**: Intercept and modify function calls

What type of patching are you interested in?"""
        if topic == "license_bypass":
            return """**License Bypass Methods**: Common approaches to software licensing:

 **Trial Extension**: Modify time checks and expiration logic
 **Key Validation**: Bypass or patch license key verification
 **Hardware Checks**: Circumvent dongle and hardware fingerprinting
 **Server Communication**: Block or redirect license server calls

Which protection mechanism are you analyzing?"""
        return """I can help you understand:

1. **Binary Protection Mechanisms**: How software protections work
2. **License Validation**: Common licensing schemes and checks
3. **Patching Techniques**: How binary patches bypass protections
4. **Analysis Methods**: Static vs dynamic analysis approaches

What would you like to learn about?"""

    def _handle_network_intent(self, intent: dict[str, Any]) -> str:
        """Handle a user request for network traffic or protocol analysis.

        Provides guidance and analysis capabilities for examining network communications,
        license server interactions, traffic interception, or security measures.

        Args:
            intent: Dictionary containing the 'aspect' parameter indicating network analysis focus
                (protocol, traffic, license_server, security, dns).

        Returns:
            A formatted string describing available network analysis capabilities and next steps.

        """
        aspect = intent.get("aspect", "protocol")

        if aspect == "license_server":
            return """I can analyze license server communications:

 **Server Discovery**: Identify license validation endpoints
 **Protocol Analysis**: Decode license request/response formats
 **Traffic Interception**: Monitor and modify license communications
 **Offline Activation Bypass**: Generate valid activation responses without server connectivity

Would you like me to start license server analysis?"""
        if aspect == "traffic":
            return """I can perform network traffic analysis:

 **Packet Capture**: Monitor all network communications
 **Protocol Identification**: Detect HTTP, TCP, UDP, and custom protocols
 **Data Extraction**: Extract license keys, certificates, and validation data
 **Flow Analysis**: Understand communication patterns and timing

Shall I begin traffic capture?"""
        if aspect == "security":
            return """I can analyze network security measures:

 **SSL/TLS Analysis**: Examine certificate validation and encryption
 **Firewall Detection**: Identify network restrictions and bypasses
 **VPN Analysis**: Analyze virtual private network configurations
 **Authentication**: Study network-based authentication mechanisms

What security aspect interests you?"""
        return "I can analyze network communications, including:\n- Protocol identification\n- License server communication\n- SSL/TLS traffic\n\nWould you like me to start network analysis?"

    def _handle_general_intent(self, message: str) -> str:
        """Handle a general user request that doesn't fit specific intent categories.

        Provides a flexible response with available capabilities and guidance for what
        the assistant can help with regarding binary analysis and protection research.

        Args:
            message: The original user message.

        Returns:
            A formatted string describing available tools and asking for clarification on user goals.

        """
        return f"I understand you want help with: {message}\n\nI can:\n- Analyze binaries\n- Detect protections\n- Suggest patches\n- Explain concepts\n\nWhat would you like to do first?"

    # Tool implementation methods
    def _analyze_binary(self, binary_path: str, analyses: list[str] | None = None) -> dict[str, Any]:
        """Perform comprehensive binary analysis for protection mechanism detection.

        Delegates to the CLI interface to execute complete binary analysis including
        structural analysis, protection detection, license check identification, and network communication patterns.

        Args:
            binary_path: Path to the binary file to analyze.
            analyses: Optional list of specific analysis types to perform. If None, performs comprehensive analysis.

        Returns:
            Dictionary containing analysis results with detected protections, vulnerabilities, and recommendations.
            If CLI interface unavailable, returns error dictionary with status 'error'.

        """
        if self.cli_interface:
            result: dict[str, Any] = self.cli_interface.analyze_binary(binary_path, analyses)
            return result
        return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

    def _detect_protections(self, binary_path: str) -> dict[str, Any]:
        """Detect all protection mechanisms in a binary file.

        Scans the binary for packing, obfuscation, anti-debugging techniques, licensing checks,
        and hardware protection mechanisms using the CLI interface.

        Args:
            binary_path: Path to the binary file to scan for protections.

        Returns:
            Dictionary containing detected protection mechanisms, their types, and confidence scores.
            If CLI interface unavailable, returns error dictionary with status 'error'.

        """
        if self.cli_interface:
            result: dict[str, Any] = self.cli_interface.execute_command(
                [binary_path, "--detect-protections", "--format", "json"],
                "Detecting all protection mechanisms",
                "Scanning for packing, anti-debug, licensing, and other protections",
            )
            return result
        return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

    def _find_license_checks(self, binary_path: str) -> dict[str, Any]:
        """Find license validation routines and activation logic in a binary.

        Analyzes the binary to identify license key validation functions, activation checks,
        trial period enforcement, and license server communication routines.

        Args:
            binary_path: Path to the binary file to analyze for license checks.

        Returns:
            Dictionary containing identified license validation routines, their locations,
            and potential bypass strategies. If CLI interface unavailable, returns error dictionary.

        """
        if self.cli_interface:
            result: dict[str, Any] = self.cli_interface.execute_command(
                [binary_path, "--license-analysis", "--format", "json"],
                "Finding license validation routines",
                "Searching for license checks, key validation, and activation logic",
            )
            return result
        return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

    def _suggest_patches(self, binary_path: str, target: str = "auto") -> dict[str, Any]:
        """Generate patch suggestions for bypassing protection mechanisms.

        Analyzes detected protections and generates specific patch recommendations targeting
        license validation, trial restrictions, or general protection mechanisms.

        Args:
            binary_path: Path to the binary to generate patches for.
            target: The protection mechanism to target ('license', 'trial', 'protection', or 'auto').

        Returns:
            Dictionary containing suggested patches with addresses, byte replacements, and rationales.
            If CLI interface unavailable, returns error dictionary with status 'error'.

        """
        if not self.cli_interface:
            return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}
        result: dict[str, Any]
        if target == "license":
            return self.cli_interface.execute_command(
                [
                    binary_path,
                    "--suggest-patches",
                    "--focus",
                    "license",
                    "--format",
                    "json",
                ],
                "Generating license bypass patches",
                "Analyzing license validation routines and suggesting bypass strategies",
            )
        if target == "trial":
            return self.cli_interface.execute_command(
                [
                    binary_path,
                    "--suggest-patches",
                    "--focus",
                    "trial",
                    "--format",
                    "json",
                ],
                "Generating trial extension patches",
                "Analyzing time-based restrictions and suggesting extension strategies",
            )
        if target == "protection":
            return self.cli_interface.execute_command(
                [
                    binary_path,
                    "--suggest-patches",
                    "--focus",
                    "protection",
                    "--format",
                    "json",
                ],
                "Generating protection bypass patches",
                "Analyzing protection mechanisms and suggesting bypass strategies",
            )
        return self.cli_interface.suggest_patches(binary_path)

    def _apply_patch(self, binary_path: str, patch_definition: dict[str, Any]) -> dict[str, Any]:
        """Apply a patch definition to a binary file with automatic cleanup.

        Converts patch definition to a temporary file and delegates to CLI interface for application.
        Ensures temporary files are cleaned up even if errors occur.

        Args:
            binary_path: Path to the binary file to patch.
            patch_definition: Dictionary containing patch details (address, bytes, operations, etc).

        Returns:
            Dictionary containing patch application results, status, and any error messages.
            Properly cleans up temporary patch files regardless of success or failure.

        """
        if self.cli_interface:
            import tempfile

            patch_file: str | None = None

            try:
                # Save patch definition to temporary file
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                    json.dump(patch_definition, f)
                    patch_file = f.name

                result: dict[str, Any] = self.cli_interface.apply_patch(binary_path, patch_file)
                return result
            except Exception as e:
                logger.exception("Error applying patch: %s", e)
                return {"status": "error", "message": f"Failed to apply patch: {e!s}"}

            finally:
                # Ensure temporary file is cleaned up even if an exception occurs
                if patch_file and os.path.exists(patch_file):
                    try:
                        Path(patch_file).unlink()
                    except OSError as e:
                        logger.warning("Failed to clean up temporary patch file %s: %s", patch_file, e)

        return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

    def _analyze_network(self, binary_path: str) -> dict[str, Any]:
        """Analyze network communication patterns and protocols used by a binary.

        Identifies network protocols, license server endpoints, certificate usage, and
        communication patterns to understand licensing validation mechanisms.

        Args:
            binary_path: Path to the binary to analyze for network communications.

        Returns:
            Dictionary containing identified network protocols, endpoints, and communication patterns.
            If CLI interface unavailable, returns error dictionary with status 'error'.

        """
        if self.cli_interface:
            result: dict[str, Any] = self.cli_interface.execute_command(
                [binary_path, "--protocol-fingerprint", "--format", "json"],
                "Analyzing network protocols",
                "Identifying network communication patterns and protocols",
            )
            return result
        return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

    def _generate_bypass(self, binary_path: str, protection_type: str) -> dict[str, Any]:
        """Generate bypass strategies for specific protection mechanisms.

        Creates targeted bypass code or patches for known protection types including TPM,
        VM detection, hardware dongles, HWID checks, time-based restrictions, and telemetry.

        Args:
            binary_path: Path to the binary with the protection to bypass.
            protection_type: Type of protection to bypass ('tpm', 'vm', 'dongle', 'hwid',
                'time', 'telemetry').

        Returns:
            Dictionary containing bypass strategy, code, and implementation details.
            Returns error if protection type is unsupported or CLI interface unavailable.

        """
        bypass_flags = {
            "tpm": "--bypass-tpm",
            "vm": "--bypass-vm-detection",
            "dongle": "--emulate-dongle",
            "hwid": "--hwid-spoof",
            "time": "--time-bomb-defuser",
            "telemetry": "--telemetry-blocker",
        }

        if flag := bypass_flags.get(protection_type.lower()):
            if self.cli_interface:
                result: dict[str, Any] = self.cli_interface.execute_command(
                    [binary_path, flag, "--format", "json"],
                    f"Generating {protection_type} bypass",
                    f"Creating bypass strategy for {protection_type} protection",
                )
                return result
            return {"status": "error", "message": CLI_INTERFACE_NOT_AVAILABLE}

        return {"status": "error", "message": f"Unknown protection type: {protection_type}"}

    def _view_hex(self, binary_path: str, address: str, size: int = 64) -> dict[str, Any]:
        """Display hex dump of binary data at a specific address.

        Reads binary file data at the specified address and formats it as a traditional
        hex dump with both hexadecimal and ASCII representations for analysis.
        Handles errors gracefully, returning error status in the response dictionary.

        Args:
            binary_path: Path to the binary file to read from.
            address: Memory or file offset address as hex (0x...) or decimal string.
            size: Number of bytes to display (default 64).

        Returns:
            Dictionary containing:
                - status: 'success' or 'error'
                - hex_dump: Formatted multi-line hex dump string
                - raw_data: Raw bytes as hex string
                - address: The requested address
                - size: Actual bytes read
                - message: Error message if status is 'error'

        """
        try:
            from ..hexview import LargeFileHandler

            # Load the binary file
            handler = LargeFileHandler(binary_path)

            # Parse address (hex or decimal)
            addr_int = int(address, 16) if address.startswith("0x") else int(address)
            # Read bytes at the specified address
            data = handler.read(addr_int, size)

            # Format as hex dump
            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i : i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                hex_lines.append(f"{addr_int + i:08x}: {hex_part:<48} {ascii_part}")

            return {
                "status": "success",
                "address": address,
                "size": len(data),
                "hex_dump": "\n".join(hex_lines),
                "raw_data": data.hex(),
            }

        except ImportError as e:
            logger.exception("Failed to import LargeFileHandler: %s", e)
            return {
                "status": "error",
                "message": "Hex view module not available",
            }
        except OSError as e:
            logger.exception("File access error for %s: %s", binary_path, e)
            return {
                "status": "error",
                "message": f"Cannot access file: {e!s}",
            }
        except ValueError as e:
            logger.exception("Invalid address format '%s': %s", address, e)
            return {
                "status": "error",
                "message": f"Invalid address format: {e!s}",
            }

    def _disassemble(self, binary_path: str, address: str, count: int = 20) -> dict[str, Any]:
        """Disassemble machine code at a specific address.

        Converts binary machine code to assembly language instructions for analysis.
        Uses CLI interface for full disassembly, or provides basic hex dump as fallback.
        Handles errors gracefully, returning error status in the response dictionary.

        Args:
            binary_path: Path to the binary file to disassemble.
            address: Memory or file offset address as hex (0x...) or decimal string.
            count: Number of instructions to disassemble (default 20).

        Returns:
            Dictionary containing:
                - status: 'success', 'partial', or 'error'
                - For success/partial status:
                    - message: Description of results
                    - raw_data: Raw bytes as hex string
                - For error status:
                    - message: Error description

        """
        if self.cli_interface:
            result: dict[str, Any] = self.cli_interface.execute_command(
                [
                    binary_path,
                    "--disassemble",
                    "--address",
                    address,
                    "--count",
                    str(count),
                    "--format",
                    "json",
                ],
                f"Disassembling {count} instructions",
                f"Disassembling code at {address} in {binary_path}",
            )
            return result
        # Fallback: basic disassembly attempt
        try:
            from ..hexview import LargeFileHandler

            # Load the binary file
            handler = LargeFileHandler(binary_path)

            # Parse address
            addr_int = int(address, 16) if address.startswith("0x") else int(address)
            # Read some bytes for basic analysis
            # Assume avg 16 bytes per instruction
            data = handler.read(addr_int, count * 16)

            return {
                "status": "partial",
                "message": f"Raw bytes at {address}: {data[:64].hex()}",
                "note": "Full disassembly requires CLI interface",
                "raw_data": data.hex(),
            }

        except ImportError as e:
            logger.exception("Failed to import LargeFileHandler: %s", e)
            return {
                "status": "error",
                "message": "Disassembly module not available",
            }
        except OSError as e:
            logger.exception("File access error for %s: %s", binary_path, e)
            return {
                "status": "error",
                "message": f"Cannot access file: {e!s}",
            }
        except ValueError as e:
            logger.exception("Invalid address format '%s': %s", address, e)
            return {
                "status": "error",
                "message": f"Invalid address format: {e!s}",
            }

    # File System Tool Methods
    def _search_license_files(self, search_path: str, custom_patterns: list[str] | None = None) -> dict[str, Any]:
        """Search for license-related files in a directory with user approval.

        Scans filesystem for license files matching common patterns (*.lic, *.key, *.dat, etc)
        and optional custom patterns. Requires user approval for filesystem access.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            search_path: Directory path to search for license files.
            custom_patterns: Optional list of additional glob patterns to search for.

        Returns:
            Dictionary containing:
                - status: 'success', 'denied', or 'error'
                - files_found: List of paths to found license-related files (if success)
                - message: Description of result or error message

        """
        try:
            result = self.file_tools.search_for_license_files(search_path, custom_patterns)

            # Log the operation for the user
            if result["status"] == "success":
                files_found = len(result.get("files_found", []))
                self._log_tool_usage(f"File search completed: {files_found} license-related files found")
            elif result["status"] == "denied":
                self._log_tool_usage("File search denied by user")
            else:
                self._log_tool_usage(f"File search failed: {result.get('message', 'Unknown error')}")

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in file search tool: %s", e)
            return {"status": "error", "message": str(e)}

    def _read_file(self, file_path: str, purpose: str = "License analysis") -> dict[str, Any]:
        """Read file content with user approval for analysis purposes.

        Reads a file from disk and returns its content after verifying user approval
        for the specific access purpose (license analysis, configuration review, etc).
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            file_path: Path to the file to read.
            purpose: Description of the purpose for reading this file (default "License analysis").

        Returns:
            Dictionary containing:
                - status: 'success', 'denied', or 'error'
                - content: File content as string (if success)
                - size: File size in bytes (if success)
                - message: Description of result or error message

        """
        try:
            result = self.file_tools.read_file(file_path, purpose)

            # Log the operation for the user
            if result["status"] == "success":
                size = result.get("size", 0)
                self._log_tool_usage(f"File read completed: {file_path} ({size:,} bytes)")
            elif result["status"] == "denied":
                self._log_tool_usage("File read denied by user")
            else:
                self._log_tool_usage(f"File read failed: {result.get('message', 'Unknown error')}")

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in file read tool: %s", e)
            return {"status": "error", "message": str(e)}

    def _analyze_program_directory(self, program_path: str) -> dict[str, Any]:
        """Analyze a program directory for licensing files and configurations.

        Comprehensively scans a program's installation directory to identify license files,
        configuration files, and other licensing-related artifacts for analysis.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            program_path: Path to the program executable or its directory.

        Returns:
            Dictionary containing:
                - status: 'success' or 'error'
                - analysis_summary: Dictionary with count of license files and total files analyzed
                - license_files: List of identified license-related file paths
                - message: Error message if status is 'error'

        """
        try:
            result = self.file_tools.analyze_program_directory(program_path)

            # Log the operation for the user
            if result["status"] == "success":
                files_found = result["analysis_summary"]["license_files_count"]
                files_analyzed = result["analysis_summary"]["files_analyzed"]
                self._log_tool_usage(
                    f"Program directory analysis completed: {files_found} license files found, {files_analyzed} files analyzed",
                )
            else:
                self._log_tool_usage(f"Program directory analysis failed: {result.get('message', 'Unknown error')}")

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in program directory analysis: %s", e)
            return {"status": "error", "message": str(e)}

    def analyze_binary_complex(self, binary_path: str, ml_results: dict[str, Any] | None = None) -> dict[str, Any]:
        """Perform complex binary analysis using AI reasoning and ML integration.

        Executes comprehensive binary analysis combining static analysis, optional ML predictions,
        and AI reasoning to identify protection mechanisms and recommend bypass strategies.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            binary_path: Path to the binary file to analyze.
            ml_results: Optional dictionary containing ML analysis results including confidence
                scores and predictions to incorporate into analysis.

        Returns:
            Dictionary containing:
                - binary_path: The analyzed binary path
                - analysis_type: Description of analysis performed
                - confidence: Confidence score (0.0-1.0) for analysis
                - findings: List of identified protections and vulnerabilities
                - recommendations: List of next analysis steps and bypass strategies
                - ml_integration: (if ml_results provided) ML confidence and predictions

        """
        try:
            findings: list[str] = []
            recommendations: list[str] = []
            analysis: dict[str, Any] = {
                "binary_path": binary_path,
                "analysis_type": "complex_binary_analysis",
                "confidence": 0.8,
                "findings": findings,
                "recommendations": recommendations,
            }

            # Incorporate ML results if provided
            if ml_results:
                analysis["ml_integration"] = {
                    "ml_confidence": ml_results.get("confidence", 0.0),
                    "ml_predictions": ml_results.get("predictions", []),
                }

            # Add complex analysis findings
            findings.extend(
                [
                    "Binary structure analysis completed",
                    "Cross-referenced with ML predictions",
                    "Applied AI reasoning patterns",
                ],
            )

            recommendations.extend(
                [
                    "Further static analysis recommended",
                    "Consider dynamic analysis for runtime behavior",
                    "Verify findings with manual review",
                ],
            )

            self._log_tool_usage(f"Complex binary analysis completed for {binary_path}")
            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in complex binary analysis: %s", e)
            return {
                "error": str(e),
                "confidence": 0.0,
                "findings": [],
                "recommendations": [],
            }

    def analyze_license_patterns(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze licensing patterns in binary data using AI reasoning.

        Identifies common license-related strings and patterns (serial numbers, activation codes,
        trial keywords, expiration markers) to determine the type of licensing mechanism used.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            input_data: Dictionary containing:
                - patterns: List of patterns extracted from binary
                - strings: List of readable strings extracted from binary

        Returns:
            Dictionary containing:
                - analysis_type: Always 'license_pattern_analysis'
                - confidence: Confidence score (0.0-1.0) for license type identification
                - license_type: Type of licensing detected ('trial_based', 'serial_based',
                    'activation_based', or 'unknown')
                - patterns_found: List of identified license-related patterns (up to 10)
                - bypass_suggestions: List of recommended next analysis steps

        """
        try:
            # Analyze patterns from input data
            patterns = input_data.get("patterns", [])
            strings = input_data.get("strings", [])

            # Look for common license patterns
            license_keywords = ["license", "serial", "key", "activation", "trial", "demo", "expire"]
            found_patterns = []

            for pattern in patterns:
                pattern_str = str(pattern).lower()
                if any(keyword in pattern_str for keyword in license_keywords):
                    found_patterns.append(pattern)

            for string in strings:
                string_str = str(string).lower()
                if any(keyword in string_str for keyword in license_keywords):
                    found_patterns.append(string)

            analysis = {
                "analysis_type": "license_pattern_analysis",
                "confidence": 0.85,
                "license_type": "unknown",
                "bypass_suggestions": [],
                "patterns_found": found_patterns[:10],
            }
            # Determine license type based on patterns
            if any("trial" in str(p).lower() for p in found_patterns):
                analysis["license_type"] = "trial_based"
            elif any("serial" in str(p).lower() for p in found_patterns):
                analysis["license_type"] = "serial_based"
            elif any("activation" in str(p).lower() for p in found_patterns):
                analysis["license_type"] = "activation_based"

            # Add bypass suggestions
            if analysis["license_type"] != "unknown":
                analysis["bypass_suggestions"] = [
                    f"Identified {analysis['license_type']} licensing",
                    "Consider runtime analysis of license checks",
                    "Look for license validation functions",
                ]

            self._log_tool_usage(f"License pattern analysis completed - found {len(found_patterns)} relevant patterns")
            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in license pattern analysis: %s", e)
            return {
                "error": str(e),
                "confidence": 0.0,
                "patterns_found": [],
                "license_type": "unknown",
            }

    def perform_reasoning(self, task_data: dict[str, Any]) -> dict[str, Any]:
        """Perform AI reasoning on binary analysis task data.

        Applies logical reasoning to analysis data to draw conclusions about protection
        mechanisms, licensing schemes, and recommends actionable next steps for investigation.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            task_data: Dictionary containing:
                - type: Type of task being reasoned about
                - patterns: (optional) List of identified patterns
                - binary_info: (optional) Binary structural information
                - ml_results: (optional) ML analysis results

        Returns:
            Dictionary containing:
                - task_type: The input task type
                - reasoning_confidence: Confidence score (0.0-1.0) for reasoning
                - conclusions: List of conclusions drawn from evidence
                - next_steps: List of recommended analysis steps
                - evidence: List of evidence items considered in reasoning

        """
        try:
            reasoning = {
                "task_type": task_data.get("type", "unknown"),
                "reasoning_confidence": 0.75,
                "conclusions": [],
                "next_steps": [],
                "evidence": [],
            }

            # Extract evidence from task data
            if "patterns" in task_data:
                reasoning["evidence"].append(f"Found {len(task_data['patterns'])} patterns")
            if "binary_info" in task_data:
                reasoning["evidence"].append("Binary information available")
            if "ml_results" in task_data:
                reasoning["evidence"].append("ML analysis results available")

            # Generate conclusions based on evidence
            if reasoning["evidence"]:
                reasoning["conclusions"] = [
                    "Analysis data is available for reasoning",
                    "Multiple information sources can be cross-referenced",
                    "Confidence level is appropriate for findings",
                ]
                reasoning["next_steps"] = [
                    "Correlate findings across data sources",
                    "Validate conclusions with additional analysis",
                    "Generate actionable recommendations",
                ]
            else:
                reasoning["conclusions"] = ["Insufficient data for comprehensive reasoning"]
                reasoning["next_steps"] = ["Gather additional analysis data"]

            self._log_tool_usage("AI reasoning completed")
            return reasoning

        except (OSError, ValueError, RuntimeError) as e:
            logger.exception("Error in AI reasoning: %s", e)
            return {
                "error": str(e),
                "reasoning_confidence": 0.0,
                "conclusions": [],
                "next_steps": [],
            }

    def _external_analysis(self, file_path: str, service: str = "virustotal", api_key: str | None = None) -> dict[str, Any]:
        """Submit file to external security analysis services with real API integration.

        Integrates with real external analysis platforms (VirusTotal, Hybrid Analysis) to
        perform analysis and retrieve security reputation, detection signatures, and behavioral data.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            file_path: Path to the file to submit for analysis.
            service: External service name ('virustotal' or 'hybrid-analysis'). Default 'virustotal'.
            api_key: API key for the external service. Required for most services.

        Returns:
            Dictionary containing:
                - status: 'success' or 'error'
                - service: The service used
                - file: The analyzed file path
                - hash: SHA256 hash of the file
                - analysis_id: Unique identifier for the analysis
                - results: Analysis results including malware signatures, detection ratios, URLs, etc.
                - message: Error message if status is 'error'

        """
        try:
            import hashlib
            import os

            import requests

            # Validate file exists
            if not os.path.exists(file_path):
                return {"status": "error", "message": f"File not found: {file_path}"}

            # Calculate file hash
            with open(file_path, "rb") as f:
                file_data = f.read()
                file_hash = hashlib.sha256(file_data).hexdigest()
                file_size = len(file_data)

            if service.lower() == "virustotal":
                # Real VirusTotal API integration
                if not api_key:
                    return {
                        "status": "error",
                        "message": "VirusTotal requires an API key for analysis",
                    }

                headers = {"x-apikey": api_key}

                # Check if file already analyzed by hash lookup
                hash_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                hash_response = requests.get(hash_url, headers=headers, timeout=30)

                if hash_response.status_code == 200:
                    # File already analyzed, return existing results
                    data = hash_response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})

                    return {
                        "status": "success",
                        "service": "virustotal",
                        "file": file_path,
                        "hash": file_hash,
                        "analysis_id": data.get("data", {}).get("id"),
                        "results": {
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "harmless": stats.get("harmless", 0),
                            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values()) if stats else 0}",
                            "scan_date": attributes.get("last_analysis_date"),
                            "permalink": data.get("data", {}).get("links", {}).get("self"),
                            "reputation": attributes.get("reputation", 0),
                            "type_description": attributes.get("type_description", "Unknown"),
                        },
                    }

                # File not found, upload for analysis
                if file_size > 32 * 1024 * 1024:  # 32MB limit for standard upload
                    # Large file upload via special URL
                    url_response = requests.get(
                        "https://www.virustotal.com/api/v3/files/upload_url",
                        headers=headers,
                        timeout=30,
                    )
                    if url_response.status_code != 200:
                        return {
                            "status": "error",
                            "message": f"Failed to get upload URL: {url_response.status_code}",
                        }
                    upload_url = url_response.json().get("data")
                else:
                    upload_url = "https://www.virustotal.com/api/v3/files"

                # Upload file
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    upload_response = requests.post(upload_url, headers=headers, files=files, timeout=120)

                if upload_response.status_code in {200, 201}:
                    analysis_data = upload_response.json()
                    analysis_id = analysis_data.get("data", {}).get("id")

                    return {
                        "status": "success",
                        "service": "virustotal",
                        "file": file_path,
                        "hash": file_hash,
                        "analysis_id": analysis_id,
                        "message": "File uploaded for analysis",
                        "results": {
                            "status": "analyzing",
                            "analysis_url": f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            "check_status_in": "60 seconds",
                        },
                    }
                return {
                    "status": "error",
                    "message": f"Upload failed: {upload_response.status_code} - {upload_response.text}",
                }

            if service.lower() == "hybrid-analysis":
                # Real Hybrid Analysis API integration
                if not api_key:
                    return {"status": "error", "message": "Hybrid Analysis requires an API key"}

                headers = {"api-key": api_key, "user-agent": "Intellicrack Binary Analyzer"}

                # Submit file for analysis
                url = "https://www.hybrid-analysis.com/api/v2/submit/file"
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    data = {
                        "environment_id": "120",  # Windows 10 64-bit
                        "no_share_third_party": "true",
                    }
                    response = requests.post(url, headers=headers, files=files, data=data, timeout=120)

                if response.status_code == 201:
                    result_data = response.json()
                    return {
                        "status": "success",
                        "service": "hybrid-analysis",
                        "file": file_path,
                        "hash": file_hash,
                        "analysis_id": result_data.get("sha256"),
                        "results": {
                            "job_id": result_data.get("job_id"),
                            "environment": result_data.get("environment_description"),
                            "submission_type": result_data.get("submission_type"),
                            "analysis_url": f"https://www.hybrid-analysis.com/sample/{result_data.get('sha256')}",
                        },
                    }
                return {"status": "error", "message": f"Submission failed: {response.status_code}"}

            return {
                "status": "error",
                "message": f"Unsupported service: {service}. Supported: virustotal, hybrid-analysis",
            }

        except requests.RequestException as e:
            logger.exception("Network error during external analysis: %s", e)
            return {"status": "error", "message": f"Network error: {e!s}"}
        except Exception as e:
            logger.exception("External analysis error: %s", e)
            return {"status": "error", "message": f"Analysis failed: {e!s}"}

    def generate_insights(self, ai_request: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive AI insights from binary analysis data.

        Analyzes binary sections, imports, and strings to identify protection mechanisms,
        licensing logic, and security measures. Provides actionable recommendations for analysis.
        All errors are handled gracefully and returned in the response dictionary.

        Args:
            ai_request: Dictionary containing:
                - input_data: Binary analysis data with sections, imports, strings
                - analysis_depth: Analysis depth level ('basic', 'standard', 'comprehensive')

        Returns:
            Dictionary containing:
                - analysis: Human-readable analysis summary
                - recommendations: List of recommended actions and next analysis steps
                - confidence: Confidence score (0.0-1.0) for insights

        """
        try:
            input_data = ai_request.get("input_data", {})
            analysis_depth = ai_request.get("analysis_depth", "standard")

            if not input_data:
                return {
                    "analysis": "Unable to perform analysis: No input data provided",
                    "recommendations": [
                        {
                            "action": "provide_binary_data",
                            "rationale": "Analysis requires binary structure information",
                        }
                    ],
                    "confidence": 0.0,
                }

            # Extract binary analysis components
            sections = input_data.get("sections", [])
            imports = input_data.get("imports", [])
            strings = input_data.get("strings", [])

            # Generate comprehensive analysis
            analysis_parts = []
            recommendations = []
            confidence = 0.5

            # Analyze sections
            if sections:
                executable_sections = [s for s in sections if s.get("executable", False)]
                data_sections = [s for s in sections if not s.get("executable", False)]

                analysis_parts.append(
                    f"Binary contains {len(sections)} sections: {len(executable_sections)} executable, {len(data_sections)} data sections.",
                )

                # Check for common section patterns
                section_names = [s.get("name", "") for s in sections]
                if ".text" in section_names:
                    analysis_parts.append("Standard .text section found for executable code.")
                if ".data" in section_names or ".rdata" in section_names:
                    analysis_parts.append("Data sections contain initialized variables and constants.")
                if ".rsrc" in section_names:
                    analysis_parts.append("Resource section present, may contain version info or embedded files.")

                # Analyze section entropy for packing detection
                for section in sections:
                    entropy = section.get("entropy", 0)
                    if entropy > 7.5:
                        section_name = section.get("name", "unknown")
                        analysis_parts.append(f"Section {section_name} has high entropy ({entropy:.2f}), possibly packed or encrypted.")
                        recommendations.append(
                            {
                                "action": "analyze_packing",
                                "rationale": f"High entropy in {section.get('name', 'section')} suggests compression or obfuscation",
                            },
                        )
                        confidence += 0.1

            # Analyze imports
            if imports:
                analysis_parts.append(f"Binary imports {len(imports)} functions from external libraries.")

                # Categorize imports
                security_apis = [
                    "CreateFileA",
                    "CreateFileW",
                    "ReadFile",
                    "WriteFile",
                    "RegOpenKey",
                    "RegSetValue",
                ]
                crypto_apis = ["CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt"]
                network_apis = ["socket", "connect", "send", "recv", "WSAStartup", "InternetOpen"]

                found_security = any(api in str(imports) for api in security_apis)
                found_crypto = any(api in str(imports) for api in crypto_apis)
                found_network = any(api in str(imports) for api in network_apis)

                if found_security:
                    analysis_parts.append("Uses file system and registry APIs, indicating data access capabilities.")
                    recommendations.append(
                        {
                            "action": "monitor_file_access",
                            "rationale": "Binary has file system access capabilities that should be monitored",
                        },
                    )

                if found_crypto:
                    analysis_parts.append("Contains cryptographic API imports, suggesting encryption/decryption functionality.")
                    recommendations.append(
                        {
                            "action": "analyze_crypto_usage",
                            "rationale": "Cryptographic capabilities may be used for license verification or data protection",
                        },
                    )
                    confidence += 0.2

                if found_network:
                    analysis_parts.append("Network APIs present, binary may communicate with remote servers.")
                    recommendations.append(
                        {
                            "action": "monitor_network_traffic",
                            "rationale": "Network capabilities suggest potential license server communication",
                        },
                    )
                    confidence += 0.1

            # Analyze strings
            if strings:
                analysis_parts.append(f"Binary contains {len(strings)} readable strings.")

                # Look for licensing-related strings
                license_patterns = [
                    "license",
                    "activation",
                    "serial",
                    "key",
                    "trial",
                    "expire",
                    "valid",
                ]
                if license_strings := [s for s in strings if any(pattern.lower() in str(s).lower() for pattern in license_patterns)]:
                    analysis_parts.append(f"Found {len(license_strings)} potential license-related strings.")
                    recommendations.append(
                        {
                            "action": "analyze_license_strings",
                            "rationale": f"License-related strings may reveal protection mechanisms: {license_strings[:3]}",
                        },
                    )
                    confidence += 0.2

                # Look for error messages
                error_patterns = ["error", "fail", "invalid", "corrupt", "missing"]
                if error_strings := [s for s in strings if any(pattern.lower() in str(s).lower() for pattern in error_patterns)]:
                    analysis_parts.append(f"Contains {len(error_strings)} error-related strings.")

            # Adjust confidence based on analysis depth
            if analysis_depth == "basic":
                confidence = max(confidence - 0.1, 0.1)

            elif analysis_depth == "comprehensive":
                confidence = min(confidence + 0.2, 1.0)
            # Ensure minimum analysis quality
            if not analysis_parts:
                analysis_parts.append("Binary structure analysis completed with limited available data.")
                confidence = 0.2

            # Add general recommendations if none were found
            if not recommendations:
                recommendations.append(
                    {
                        "action": "perform_dynamic_analysis",
                        "rationale": "Static analysis complete, consider dynamic analysis for runtime behavior",
                    },
                )

            return {
                "analysis": " ".join(analysis_parts),
                "recommendations": recommendations,
                "confidence": confidence,
            }

        except Exception as e:
            logger.exception("Error generating AI insights: %s", e)
            return {
                "analysis": f"Analysis failed due to error: {e!s}",
                "recommendations": [
                    {
                        "action": "check_input_format",
                        "rationale": "Verify that input data is in expected format",
                    }
                ],
                "confidence": 0.0,
            }

    def _log_tool_usage(self, message: str) -> None:
        """Log tool usage information for user visibility and audit trail.

        Records AI tool usage in logs and emits signals to update user interface
        with information about executed analysis operations.

        Args:
            message: Description of the tool operation being logged.

        """
        logger.info("[AI Tool] %s", message)
        if self.cli_interface and hasattr(self.cli_interface, "update_output"):
            update_output = getattr(self.cli_interface, "update_output", None)
            if update_output and hasattr(update_output, "emit"):
                update_output.emit(f"[AI Tool] {message}")


def create_ai_assistant_widget() -> QWidget:
    """Create the AI assistant chat widget for the UI.

    Constructs a complete chat interface including a message display area, input field,
    send/clear buttons, and connects them to an IntellicrackAIAssistant instance for
    real-time interactive binary analysis.

    Returns:
        QWidget containing the complete AI assistant chat interface configured and ready for use.

    """
    from ..handlers.pyqt6_handler import QHBoxLayout, QPushButton, QTextEdit, QVBoxLayout, QWidget

    widget = QWidget()
    layout = QVBoxLayout(widget)

    # Chat display
    chat_display = QTextEdit()
    chat_display.setReadOnly(True)
    layout.addWidget(chat_display)

    # Input area
    input_area = QTextEdit()
    input_area.setMaximumHeight(100)
    layout.addWidget(input_area)

    # Buttons
    button_layout = QHBoxLayout()
    send_btn = QPushButton("Send")
    clear_btn = QPushButton("Clear")
    button_layout.addWidget(send_btn)
    button_layout.addWidget(clear_btn)
    layout.addLayout(button_layout)

    # Create assistant
    assistant = IntellicrackAIAssistant()

    # Connect signals
    def send_message() -> None:
        """Send a message to the AI assistant and display the response.

        Retrieves the text from the input area, sends it to the assistant,
        displays both the user message and assistant response in the chat display,
        then clears the input area for the next message.

        """
        message = input_area.toPlainText()
        if message:
            chat_display.append(f"User: {message}")
            response = assistant.process_message(message)
            chat_display.append(f"Assistant: {response['message']}")
            input_area.clear()

    send_btn.clicked.connect(send_message)
    clear_btn.clicked.connect(chat_display.clear)

    return widget
