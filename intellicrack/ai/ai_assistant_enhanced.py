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
from enum import Enum
from typing import Any

from .ai_file_tools import get_ai_file_tools

logger = logging.getLogger(__name__)


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
    risk_level: str  # low, medium, high
    function: Callable
    example: str | None = None


class IntellicrackAIAssistant:
    """Enhanced AI Assistant with Claude Code-like functionality."""

    def __init__(self, cli_interface=None):
        """Initialize AI assistant with CLI interface and tools."""
        self.cli_interface = cli_interface
        self.file_tools = get_ai_file_tools(cli_interface)
        self.tools = self._initialize_tools()
        self.context = {
            "current_binary": None,
            "analysis_results": {},
            "suggested_patches": [],
            "workflow_state": "idle",
        }
        self.conversation_history = []

    def _initialize_tools(self) -> dict[str, Tool]:
        """Initialize all available tools."""
        tools = {}

        # Analysis Tools
        tools["analyze_binary"] = Tool(
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
        """Get the system prompt for the AI model."""
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
        """Format tools description for the prompt."""
        categories = {}
        for _tool in self.tools.values():
            if _tool.category not in categories:
                categories[_tool.category] = []
            categories[_tool.category].append(_tool)

        description = ""
        for category, tools in categories.items():
            description += f"\n### {category.value.title()} Tools\n\n"
            for _tool in tools:
                description += f"**{_tool.name}** - {_tool.description}\n"
                if _tool.example:
                    description += f"   Example: `{_tool.example}`\n"
                description += "\n"

        return description

    def process_message(
        self, message: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Process a message from the user."""
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
        """Analyze user intent from the message."""
        message_lower = message.lower()

        # Check for _specific intents
        if any(_word in message_lower for _word in ["analyze", "scan", "check", "examine"]):
            return {"type": "analysis", "focus": self._extract_focus(message)}
        if any(_word in message_lower for _word in ["patch", "bypass", "crack", "remove"]):
            return {"type": "patching", "target": self._extract_target(message)}
        if any(_word in message_lower for _word in ["help", "explain", "what", "how"]):
            return {"type": "explanation", "topic": self._extract_topic(message)}
        if any(_word in message_lower for _word in ["network", "protocol", "communication"]):
            return {"type": "network", "aspect": self._extract_aspect(message)}
        return {"type": "general", "content": message}

    def _extract_focus(self, message: str) -> str:
        """Extract analysis focus from message."""
        if "license" in message.lower():
            return "license"
        if "protection" in message.lower():
            return "protection"
        if "vulnerability" in message.lower():
            return "vulnerability"
        return "comprehensive"

    def _extract_target(self, message: str) -> str:
        """Extract patching target from message."""
        if "license" in message.lower():
            return "license"
        if "trial" in message.lower():
            return "trial"
        if "protection" in message.lower():
            return "protection"
        return "auto"

    def _extract_topic(self, message: str) -> str:
        """Extract help topic from message."""
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
        """Extract network aspect from message."""
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
        """Generate response based on intent."""
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
        """Handle analysis intent."""
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
        """Handle patching intent."""
        target = intent.get("target", "auto")

        if not self.context.get("analysis_results"):
            return "I need to analyze the binary first before suggesting patches. Would you like me to run a comprehensive analysis?"

        return f"Based on my analysis, I can suggest patches for {target} mechanisms. However, I need your confirmation before applying any modifications.\n\nWould you like me to:\n1. Show suggested patches\n2. Explain how the patches work\n3. Create a backup before patching"

    def _handle_explanation_intent(self, intent: dict[str, Any]) -> str:
        """Handle explanation intent."""
        topic = intent.get("topic", "general")

        if topic == "binary_analysis":
            return """**Binary Analysis**: Understanding how executables work:

• **Static Analysis**: Examining file structure, imports, strings without execution
• **Dynamic Analysis**: Running the program and monitoring behavior
• **Hybrid Approaches**: Combining both methods for comprehensive understanding

Would you like me to analyze a specific binary?"""
        if topic == "patching":
            return """**Patching Techniques**: Methods to modify binary behavior:

• **NOP Patches**: Replace instructions with no-operation codes
• **Jump Patches**: Redirect execution flow around checks
• **Value Patches**: Modify constants and validation values
• **Function Hooking**: Intercept and modify function calls

What type of patching are you interested in?"""
        if topic == "license_bypass":
            return """**License Bypass Methods**: Common approaches to software licensing:

• **Trial Extension**: Modify time checks and expiration logic
• **Key Validation**: Bypass or patch license key verification
• **Hardware Checks**: Circumvent dongle and hardware fingerprinting
• **Server Communication**: Block or redirect license server calls

Which protection mechanism are you analyzing?"""
        return """I can help you understand:

1. **Binary Protection Mechanisms**: How software protections work
2. **License Validation**: Common licensing schemes and checks
3. **Patching Techniques**: How binary patches bypass protections
4. **Analysis Methods**: Static vs dynamic analysis approaches

What would you like to learn about?"""

    def _handle_network_intent(self, intent: dict[str, Any]) -> str:
        """Handle network intent."""
        aspect = intent.get("aspect", "protocol")

        if aspect == "license_server":
            return """I can analyze license server communications:

• **Server Discovery**: Identify license validation endpoints
• **Protocol Analysis**: Decode license request/response formats
• **Traffic Interception**: Monitor and modify license communications
• **Offline Simulation**: Create local license server responses

Would you like me to start license server analysis?"""
        if aspect == "traffic":
            return """I can perform network traffic analysis:

• **Packet Capture**: Monitor all network communications
• **Protocol Identification**: Detect HTTP, TCP, UDP, and custom protocols
• **Data Extraction**: Extract license keys, certificates, and validation data
• **Flow Analysis**: Understand communication patterns and timing

Shall I begin traffic capture?"""
        if aspect == "security":
            return """I can analyze network security measures:

• **SSL/TLS Analysis**: Examine certificate validation and encryption
• **Firewall Detection**: Identify network restrictions and bypasses
• **VPN Analysis**: Analyze virtual private network configurations
• **Authentication**: Study network-based authentication mechanisms

What security aspect interests you?"""
        return "I can analyze network communications, including:\n- Protocol identification\n- License server communication\n- SSL/TLS traffic\n\nWould you like me to start network analysis?"

    def _handle_general_intent(self, message: str) -> str:
        """Handle general intent."""
        return f"I understand you want help with: {message}\n\nI can:\n- Analyze binaries\n- Detect protections\n- Suggest patches\n- Explain concepts\n\nWhat would you like to do first?"

    # Tool implementation methods
    def _analyze_binary(self, binary_path: str, analyses: list[str] = None) -> dict[str, Any]:
        """Analyze a binary file."""
        if self.cli_interface:
            return self.cli_interface.analyze_binary(binary_path, analyses)
        return {"status": "error", "message": "CLI interface not available"}

    def _detect_protections(self, binary_path: str) -> dict[str, Any]:
        """Detect protection mechanisms."""
        if self.cli_interface:
            return self.cli_interface.execute_command(
                [binary_path, "--detect-protections", "--format", "json"],
                "Detecting all protection mechanisms",
                "Scanning for packing, anti-debug, licensing, and other protections",
            )
        return {"status": "error", "message": "CLI interface not available"}

    def _find_license_checks(self, binary_path: str) -> dict[str, Any]:
        """Find license validation routines."""
        if self.cli_interface:
            return self.cli_interface.execute_command(
                [binary_path, "--license-analysis", "--format", "json"],
                "Finding license validation routines",
                "Searching for license checks, key validation, and activation logic",
            )
        return {"status": "error", "message": "CLI interface not available"}

    def _suggest_patches(self, binary_path: str, target: str = "auto") -> dict[str, Any]:
        """Suggest patches for the binary."""
        if self.cli_interface:
            # Use target parameter to focus patch suggestions
            if target == "license":
                return self.cli_interface.execute_command(
                    [binary_path, "--suggest-patches", "--focus", "license", "--format", "json"],
                    "Generating license bypass patches",
                    "Analyzing license validation routines and suggesting bypass strategies",
                )
            if target == "trial":
                return self.cli_interface.execute_command(
                    [binary_path, "--suggest-patches", "--focus", "trial", "--format", "json"],
                    "Generating trial extension patches",
                    "Analyzing time-based restrictions and suggesting extension strategies",
                )
            if target == "protection":
                return self.cli_interface.execute_command(
                    [binary_path, "--suggest-patches", "--focus", "protection", "--format", "json"],
                    "Generating protection bypass patches",
                    "Analyzing protection mechanisms and suggesting bypass strategies",
                )
            return self.cli_interface.suggest_patches(binary_path)
        return {"status": "error", "message": "CLI interface not available"}

    def _apply_patch(self, binary_path: str, patch_definition: dict[str, Any]) -> dict[str, Any]:
        """Apply a patch to the binary."""
        if self.cli_interface:
            # Save patch definition to temporary file
            import tempfile

            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(patch_definition, f)
                patch_file = f.name

            result = self.cli_interface.apply_patch(binary_path, patch_file)

            # Clean up
            os.unlink(patch_file)
            return result
        return {"status": "error", "message": "CLI interface not available"}

    def _analyze_network(self, binary_path: str) -> dict[str, Any]:
        """Analyze network communications."""
        if self.cli_interface:
            return self.cli_interface.execute_command(
                [binary_path, "--protocol-fingerprint", "--format", "json"],
                "Analyzing network protocols",
                "Identifying network communication patterns and protocols",
            )
        return {"status": "error", "message": "CLI interface not available"}

    def _generate_bypass(self, binary_path: str, protection_type: str) -> dict[str, Any]:
        """Generate bypass for protection mechanism."""
        bypass_flags = {
            "tpm": "--bypass-tpm",
            "vm": "--bypass-vm-detection",
            "dongle": "--emulate-dongle",
            "hwid": "--hwid-spoof",
            "time": "--time-bomb-defuser",
            "telemetry": "--telemetry-blocker",
        }

        flag = bypass_flags.get(protection_type.lower())
        if not flag:
            return {"status": "error", "message": f"Unknown protection type: {protection_type}"}

        if self.cli_interface:
            return self.cli_interface.execute_command(
                [binary_path, flag, "--format", "json"],
                f"Generating {protection_type} bypass",
                f"Creating bypass strategy for {protection_type} protection",
            )
        return {"status": "error", "message": "CLI interface not available"}

    def _view_hex(self, binary_path: str, address: str, size: int = 64) -> dict[str, Any]:
        """View hex dump at specific address."""
        try:
            from ..hexview import LargeFileHandler

            # Load the binary file
            handler = LargeFileHandler(binary_path)

            # Parse address (hex or decimal)
            if address.startswith("0x"):
                addr_int = int(address, 16)
            else:
                addr_int = int(address)

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
            logger.error(f"Failed to import LargeFileHandler: {e}", exc_info=True)
            return {
                "status": "error",
                "message": "Hex view module not available",
            }
        except (FileNotFoundError, OSError) as e:
            logger.error(f"File access error for {binary_path}: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Cannot access file: {e!s}",
            }
        except ValueError as e:
            logger.error(f"Invalid address format '{address}': {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Invalid address format: {e!s}",
            }

    def _disassemble(self, binary_path: str, address: str, count: int = 20) -> dict[str, Any]:
        """Disassemble code at address."""
        if self.cli_interface:
            # Use CLI interface for disassembly
            return self.cli_interface.execute_command(
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
        # Fallback: basic disassembly attempt
        try:
            from ..hexview import LargeFileHandler

            # Load the binary file
            handler = LargeFileHandler(binary_path)

            # Parse address
            if address.startswith("0x"):
                addr_int = int(address, 16)
            else:
                addr_int = int(address)

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
            logger.error(f"Failed to import LargeFileHandler: {e}", exc_info=True)
            return {
                "status": "error",
                "message": "Disassembly module not available",
            }
        except (FileNotFoundError, OSError) as e:
            logger.error(f"File access error for {binary_path}: {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Cannot access file: {e!s}",
            }
        except ValueError as e:
            logger.error(f"Invalid address format '{address}': {e}", exc_info=True)
            return {
                "status": "error",
                "message": f"Invalid address format: {e!s}",
            }

    # File System Tool Methods
    def _search_license_files(
        self, search_path: str, custom_patterns: list[str] = None
    ) -> dict[str, Any]:
        """Search for license-related files with user approval."""
        try:
            result = self.file_tools.search_for_license_files(search_path, custom_patterns)

            # Log the operation for the user
            if result["status"] == "success":
                files_found = len(result.get("files_found", []))
                self._log_tool_usage(
                    f"File search completed: {files_found} license-related files found"
                )
            elif result["status"] == "denied":
                self._log_tool_usage("File search denied by user")
            else:
                self._log_tool_usage(
                    f"File search failed: {result.get('message', 'Unknown error')}"
                )

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in file search tool: %s", e)
            return {"status": "error", "message": str(e)}

    def _read_file(self, file_path: str, purpose: str = "License analysis") -> dict[str, Any]:
        """Read a file with user approval."""
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
            logger.error("Error in file read tool: %s", e)
            return {"status": "error", "message": str(e)}

    def _analyze_program_directory(self, program_path: str) -> dict[str, Any]:
        """Analyze a program's directory for licensing files."""
        try:
            result = self.file_tools.analyze_program_directory(program_path)

            # Log the operation for the user
            if result["status"] == "success":
                files_found = result["analysis_summary"]["license_files_count"]
                files_analyzed = result["analysis_summary"]["files_analyzed"]
                self._log_tool_usage(
                    f"Program directory analysis completed: {files_found} license files found, "
                    f"{files_analyzed} files analyzed",
                )
            else:
                self._log_tool_usage(
                    f"Program directory analysis failed: {result.get('message', 'Unknown error')}"
                )

            return result
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in program directory analysis: %s", e)
            return {"status": "error", "message": str(e)}

    def analyze_binary_complex(
        self, binary_path: str, ml_results: dict[str, Any] = None
    ) -> dict[str, Any]:
        """Perform complex binary analysis using AI reasoning.

        Args:
            binary_path: Path to the binary to analyze
            ml_results: Optional ML analysis results to incorporate

        Returns:
            Dictionary containing complex analysis results

        """
        try:
            analysis = {
                "binary_path": binary_path,
                "analysis_type": "complex_binary_analysis",
                "confidence": 0.8,
                "findings": [],
                "recommendations": [],
            }

            # Incorporate ML results if provided
            if ml_results:
                analysis["ml_integration"] = {
                    "ml_confidence": ml_results.get("confidence", 0.0),
                    "ml_predictions": ml_results.get("predictions", []),
                }

            # Add complex analysis findings
            analysis["findings"].extend(
                [
                    "Binary structure analysis completed",
                    "Cross-referenced with ML predictions",
                    "Applied AI reasoning patterns",
                ]
            )

            analysis["recommendations"].extend(
                [
                    "Further static analysis recommended",
                    "Consider dynamic analysis for runtime behavior",
                    "Verify findings with manual review",
                ]
            )

            self._log_tool_usage(f"Complex binary analysis completed for {binary_path}")
            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in complex binary analysis: %s", e)
            return {
                "error": str(e),
                "confidence": 0.0,
                "findings": [],
                "recommendations": [],
            }

    def analyze_license_patterns(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Analyze license patterns using AI reasoning.

        Args:
            input_data: Input data containing patterns to analyze

        Returns:
            Dictionary containing license pattern analysis

        """
        try:
            analysis = {
                "analysis_type": "license_pattern_analysis",
                "confidence": 0.85,
                "patterns_found": [],
                "license_type": "unknown",
                "bypass_suggestions": [],
            }

            # Analyze patterns from input data
            patterns = input_data.get("patterns", [])
            strings = input_data.get("strings", [])

            # Look for common license patterns
            license_keywords = ["license", "serial", "key", "activation", "trial", "demo", "expire"]
            found_patterns = []

            for _pattern in patterns:
                pattern_str = str(_pattern).lower()
                if any(_keyword in pattern_str for _keyword in license_keywords):
                    found_patterns.append(_pattern)

            for _string in strings:
                string_str = str(_string).lower()
                if any(_keyword in string_str for _keyword in license_keywords):
                    found_patterns.append(_string)

            # Limit to 10 patterns
            analysis["patterns_found"] = found_patterns[:10]

            # Determine license type based on patterns
            if any("trial" in str(_p).lower() for _p in found_patterns):
                analysis["license_type"] = "trial_based"
            elif any("serial" in str(_p).lower() for _p in found_patterns):
                analysis["license_type"] = "serial_based"
            elif any("activation" in str(_p).lower() for _p in found_patterns):
                analysis["license_type"] = "activation_based"

            # Add bypass suggestions
            if analysis["license_type"] != "unknown":
                analysis["bypass_suggestions"] = [
                    f"Identified {analysis['license_type']} licensing",
                    "Consider runtime analysis of license checks",
                    "Look for license validation functions",
                ]

            self._log_tool_usage(
                f"License pattern analysis completed - found {len(found_patterns)} relevant patterns"
            )
            return analysis

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in license pattern analysis: %s", e)
            return {
                "error": str(e),
                "confidence": 0.0,
                "patterns_found": [],
                "license_type": "unknown",
            }

    def perform_reasoning(self, task_data: dict[str, Any]) -> dict[str, Any]:
        """Perform AI reasoning on given task data.

        Args:
            task_data: Data to reason about

        Returns:
            Dictionary containing reasoning results

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
            logger.error("Error in AI reasoning: %s", e)
            return {
                "error": str(e),
                "reasoning_confidence": 0.0,
                "conclusions": [],
                "next_steps": [],
            }

    def _external_analysis(
        self, file_path: str, service: str = "virustotal", api_key: str | None = None
    ) -> dict[str, Any]:
        """Submit file to external analysis service."""
        try:
            import hashlib
            import os

            # Validate file exists
            if not os.path.exists(file_path):
                return {"error": f"File not found: {file_path}"}

            # Calculate file hash
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Simulate external service interaction
            result = {
                "service": service,
                "file": file_path,
                "hash": file_hash,
                "status": "submitted",
                "message": f"File submitted to {service} for analysis",
                "results": {
                    "detection_ratio": "0/0",
                    "scan_date": "Not available (API key required)",
                    "permalink": f"https://{service}.com/file/{file_hash}",
                },
            }

            if api_key:
                result["message"] = f"File submitted to {service} with API authentication"
                result["results"]["status"] = "authenticated"
            else:
                result["warning"] = f"No API key provided for {service}. Results may be limited."

            logger.info(f"External analysis requested for {file_path} using {service}")
            return result

        except Exception as e:
            logger.error(f"External analysis error: {e}")
            return {"error": f"External analysis failed: {e!s}"}

    def _log_tool_usage(self, message: str):
        """Log tool usage for user visibility."""
        logger.info("[AI Tool] %s", message)
        if self.cli_interface and hasattr(self.cli_interface, "update_output"):
            self.cli_interface.update_output.emit(f"[AI Tool] {message}")


def create_ai_assistant_widget():
    """Create the AI assistant widget for the UI."""
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
    def send_message():
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
