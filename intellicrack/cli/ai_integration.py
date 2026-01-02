"""AI Integration Module for Intellicrack.

This module provides integration points for various AI models (OpenAI, Anthropic, etc.)
to use Intellicrack capabilities safely. It offers model-specific adapters for Claude,
OpenAI, and LangChain frameworks to interact with Intellicrack's binary analysis and
licensing protection cracking capabilities through a controlled, confirmation-based interface.
"""

import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Any

from .ai_wrapper import ConfirmationManager, IntellicrackAIInterface


script_dir: str = os.path.dirname(os.path.abspath(__file__))
project_root: str = os.path.abspath(os.path.join(script_dir, "..", ".."))
sys.path.insert(0, project_root)


logger: logging.Logger = logging.getLogger(__name__)


class AIModelAdapter(ABC):
    """Abstract base class for AI model adapters."""

    def __init__(self, intellicrack_interface: IntellicrackAIInterface) -> None:
        """Initialize AI model adapter with Intellicrack interface and tool definitions.

        Args:
            intellicrack_interface: Interface for interacting with Intellicrack functionality.
        """
        self.interface = intellicrack_interface
        self.tools = self._create_tool_definitions()

    @abstractmethod
    def _create_tool_definitions(self) -> list[dict[str, Any]]:
        """Create tool definitions in the model's expected format.

        Returns:
            list of tool definition dictionaries in the model's format.
                Each dictionary contains model-specific tool specifications
                including name, description, and parameter schema.
        """

    @abstractmethod
    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from the AI model.

        Args:
            tool_name: Name of the tool to invoke.
            parameters: Tool parameters as a dictionary.

        Returns:
            Tool execution result containing status, message, and any output data.
        """


class ClaudeAdapter(AIModelAdapter):
    """Adapter for Anthropic Claude models."""

    @staticmethod
    def _create_tool_definitions() -> list[dict[str, Any]]:
        """Create tool definitions in Claude's format.

        Returns:
            List of tool definition dictionaries in Claude's format.
                Includes analyze_binary, suggest_patches, apply_patch, and
                execute_cli_command tools with complete input schemas.
        """
        return [
            {
                "name": "analyze_binary",
                "description": "Analyze a binary file to understand its structure, protections, and vulnerabilities",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file to analyze",
                        },
                        "analyses": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Types of analysis to perform",
                            "default": ["comprehensive"],
                        },
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "suggest_patches",
                "description": "Generate patch suggestions for bypassing protections in a binary",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file",
                        },
                    },
                    "required": ["binary_path"],
                },
            },
            {
                "name": "apply_patch",
                "description": "Apply a patch to modify a binary (requires user confirmation)",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Path to the binary file",
                        },
                        "patch_file": {
                            "type": "string",
                            "description": "Path to the patch definition file",
                        },
                    },
                    "required": ["binary_path", "patch_file"],
                },
            },
            {
                "name": "execute_cli_command",
                "description": "Execute any Intellicrack CLI command with full control",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "args": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "CLI arguments to pass",
                        },
                        "description": {
                            "type": "string",
                            "description": "Human-readable description of the action",
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Explanation of why this action is needed",
                        },
                    },
                    "required": ["args", "description"],
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from Claude.

        Processes Claude tool requests and routes them to the appropriate
        Intellicrack interface methods. Handles four main tools: analyze_binary,
        suggest_patches, apply_patch, and execute_cli_command.

        Args:
            tool_name: Name of the tool to invoke.
            parameters: Tool parameters as a dictionary.

        Returns:
            Tool execution result with status, message, and optional output.
                Returns error status and message if tool is unknown or execution
                fails.

        Raises:
            No exceptions are raised; errors are caught and returned in the
                response dictionary with status='error'.
        """
        try:
            if tool_name == "analyze_binary":
                return self.interface.analyze_binary(
                    parameters["binary_path"],
                    parameters.get("analyses", ["comprehensive"]),
                )

            if tool_name == "suggest_patches":
                return self.interface.suggest_patches(parameters["binary_path"])

            if tool_name == "apply_patch":
                return self.interface.apply_patch(
                    parameters["binary_path"],
                    parameters["patch_file"],
                )

            if tool_name == "execute_cli_command":
                return self.interface.execute_command(
                    parameters["args"],
                    parameters["description"],
                    parameters.get("reasoning"),
                )

            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}",
            }

        except Exception as e:
            logger.exception("Error handling tool call")
            return {
                "status": "error",
                "message": str(e),
            }


class OpenAIAdapter(AIModelAdapter):
    """Adapter for OpenAI models."""

    @staticmethod
    def _create_tool_definitions() -> list[dict[str, Any]]:
        """Create tool definitions in OpenAI's format.

        Returns:
            List of tool definition dictionaries in OpenAI function calling format.
                Includes analyze_binary, suggest_patches, and apply_patch tools
                with complete function parameter specifications.
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "analyze_binary",
                    "description": "Analyze a binary file to understand its structure, protections, and vulnerabilities",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary_path": {
                                "type": "string",
                                "description": "Path to the binary file",
                            },
                            "analyses": {
                                "type": "array",
                                "items": {"type": "string"},
                                "enum": [
                                    "comprehensive",
                                    "vulnerabilities",
                                    "protections",
                                    "license",
                                    "network",
                                ],
                                "description": "Types of analysis to perform",
                            },
                        },
                        "required": ["binary_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "suggest_patches",
                    "description": "Generate patch suggestions for bypassing protections",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary_path": {
                                "type": "string",
                                "description": "Path to the binary file",
                            },
                        },
                        "required": ["binary_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "apply_patch",
                    "description": "Apply a patch to modify a binary (requires confirmation)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binary_path": {
                                "type": "string",
                                "description": "Path to the binary file",
                            },
                            "patch_file": {
                                "type": "string",
                                "description": "Path to patch definition",
                            },
                        },
                        "required": ["binary_path", "patch_file"],
                    },
                },
            },
        ]

    def handle_tool_call(self, tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call from OpenAI.

        Processes OpenAI function calling requests and routes them to the
        appropriate Intellicrack interface methods. Handles multiple tools
        including binary analysis, patch suggestions, and script generation.

        Args:
            tool_name: Name of the tool to invoke.
            parameters: Tool parameters as a dictionary.

        Returns:
            Tool execution result with status, message, and optional output.
                On success, includes the tool's result data. On error, includes
                available_tools list and received_parameters for debugging.

        Raises:
            KeyError exceptions are caught and returned with missing parameter
                information. General exceptions are caught and returned with
                error_type for debugging purposes.
        """
        try:
            # Map tool names to interface methods
            if tool_name == "analyze_binary":
                analyses = parameters.get("analyses", ["comprehensive"])
                return self.interface.analyze_binary(parameters["binary_path"], analyses)

            if tool_name == "suggest_patches":
                return self.interface.suggest_patches(parameters["binary_path"])

            if tool_name == "apply_patch":
                return self.interface.apply_patch(parameters["binary_path"], parameters["patch_file"])

            if tool_name == "execute_cli_command":
                return self.interface.execute_command(parameters["args"], parameters["description"], parameters.get("reasoning", ""))

            if tool_name == "generate_frida_script":
                return self.interface.generate_frida_script(
                    parameters.get("binary_path"),
                    parameters.get("target_function"),
                    parameters.get("script_type", "hook"),
                )

            if tool_name == "generate_ghidra_script":
                return self.interface.generate_ghidra_script(
                    parameters.get("binary_path"),
                    parameters.get("analysis_type", "comprehensive"),
                )

            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}",
                "available_tools": [
                    "analyze_binary",
                    "suggest_patches",
                    "apply_patch",
                    "execute_cli_command",
                    "generate_frida_script",
                    "generate_ghidra_script",
                ],
            }

        except KeyError as e:
            logger.exception("Missing required parameter for tool %s", tool_name)
            return {
                "status": "error",
                "message": f"Missing required parameter: {e}",
                "tool": tool_name,
                "received_parameters": list(parameters.keys()),
            }

        except Exception as e:
            logger.exception("Tool execution failed for %s", tool_name)
            return {
                "status": "error",
                "message": f"Tool execution failed: {e}",
                "tool": tool_name,
                "error_type": type(e).__name__,
            }


class LangChainIntegration:
    """Integration for LangChain-based AI applications."""

    def __init__(self, intellicrack_interface: IntellicrackAIInterface) -> None:
        """Initialize LangChain integration with Intellicrack interface.

        Args:
            intellicrack_interface: Interface for interacting with Intellicrack functionality.
        """
        self.interface = intellicrack_interface

    def create_tools(self) -> list[Any]:
        """Create LangChain tool wrappers.

        Constructs Tool objects compatible with LangChain framework for
        integration with LangChain agents and chains. Falls back gracefully
        if LangChain is not installed.

        Returns:
            List of LangChain Tool objects for binary analysis operations,
                patch suggestions, and CLI command execution. Returns an empty
                list if LangChain is not available.
        """
        try:
            from langchain_core.tools import Tool

            tools: list[Any] = []

            tools.extend((
                Tool(
                    name="analyze_binary",
                    func=self._handle_analyze,
                    description="Analyze a binary file. Input: 'path/to/binary [analysis_types]'",
                ),
                Tool(
                    name="suggest_patches",
                    func=self._handle_suggest_patches,
                    description="Suggest patches for a binary. Input: 'path/to/binary'",
                ),
                Tool(
                    name="intellicrack_cli",
                    func=self._handle_cli_command,
                    description="Run Intellicrack CLI command. Input: 'description | command args'",
                ),
            ))
            return tools

        except ImportError:
            logger.exception("LangChain not available")
            return []

    def _handle_analyze(self, input_str: str) -> str:
        """Handle analyze tool call.

        Parses the input string for binary path and optional analysis types,
        then invokes the Intellicrack binary analysis interface and returns
        the result as JSON.

        Args:
            input_str: Input string containing binary path and optional analysis types.
                Format: "path/to/binary [analysis_type1 analysis_type2 ...]"

        Returns:
            JSON-formatted analysis result containing analysis data or error
                information.
        """
        parts = input_str.strip().split()
        binary_path = parts[0]
        analyses = parts[1:] if len(parts) > 1 else ["comprehensive"]

        result = self.interface.analyze_binary(binary_path, analyses)
        return json.dumps(result, indent=2)

    def _handle_suggest_patches(self, input_str: str) -> str:
        """Handle suggest patches tool call.

        Invokes the Intellicrack interface to generate patch suggestions for
        the specified binary file and returns the suggestions as JSON.

        Args:
            input_str: Binary file path as a string.

        Returns:
            JSON-formatted patch suggestions containing identified bypass points
                and patch definitions.
        """
        binary_path = input_str.strip()
        result = self.interface.suggest_patches(binary_path)
        return json.dumps(result, indent=2)

    def _handle_cli_command(self, input_str: str) -> str:
        """Handle CLI command tool call.

        Parses the input string to extract description and CLI arguments,
        then executes the command through the Intellicrack interface and
        returns the result as JSON.

        Args:
            input_str: Input in format "description | command args".

        Returns:
            JSON-formatted command execution result containing status, output,
                and any error information.
        """
        # Format: "description | command args"
        EXPECTED_PARTS_COUNT = 2
        parts = input_str.split("|", 1)
        if len(parts) != EXPECTED_PARTS_COUNT:
            return json.dumps({"error": "Invalid format. Use: 'description | command args'"})

        description = parts[0].strip()
        args = parts[1].strip().split()

        result = self.interface.execute_command(args, description)
        return json.dumps(result, indent=2)


class IntellicrackAIServer:
    """Server for AI model interactions."""

    def __init__(self, *, auto_approve_low_risk: bool = False) -> None:
        """Initialize AI server with confirmation manager and multiple AI adapters.

        Args:
            auto_approve_low_risk: Whether to automatically approve low-risk operations.
        """
        self.confirmation_manager = ConfirmationManager(auto_approve_low_risk)
        self.interface = IntellicrackAIInterface(self.confirmation_manager)
        self.adapters = {
            "claude": ClaudeAdapter(self.interface),
            "openai": OpenAIAdapter(self.interface),
            "langchain": LangChainIntegration(self.interface),
        }

    def get_adapter(self, model_type: str) -> AIModelAdapter | None:
        """Get adapter for specific model type.

        Retrieves the appropriate AI model adapter instance from the server's
        registered adapters collection.

        Args:
            model_type: Type of AI model (e.g., 'claude', 'openai').

        Returns:
            The adapter for the specified model type, or None if not found.
                Validates that the adapter is an instance of AIModelAdapter
                before returning.
        """
        adapter = self.adapters.get(model_type)
        if adapter is not None and isinstance(adapter, AIModelAdapter):
            return adapter
        return None

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        """Handle an AI model request.

        Extracts model type, tool name, and parameters from the request,
        retrieves the appropriate adapter, and invokes the tool handler.
        Validates all input and returns consistent error responses for
        invalid requests.

        Args:
            request: Request dictionary containing 'model_type', 'tool', and
                'parameters'. model_type defaults to 'claude' if not specified.

        Returns:
            Response dictionary with status, message, and tool results.
                On success, includes the tool handler's response. On error,
                includes status='error' with descriptive message.
        """
        model_type_value = request.get("model_type", "claude")
        model_type = str(model_type_value) if model_type_value is not None else "claude"
        tool_name = request.get("tool")
        parameters_value = request.get("parameters", {})
        parameters = parameters_value if isinstance(parameters_value, dict) else {}

        if tool_name is None or not isinstance(tool_name, str):
            return {
                "status": "error",
                "message": "Missing or invalid tool name",
            }

        adapter = self.get_adapter(model_type)
        if adapter is not None:
            return adapter.handle_tool_call(tool_name, parameters)
        else:
            return {
                "status": "error",
                "message": f"Unknown model type: {model_type}",
            }


def create_ai_system_prompt() -> str:
    """Create a comprehensive system prompt for AI models.

    Generates a detailed system prompt that describes all available Intellicrack
    tools, their usage, expected workflow, and important safety considerations
    for AI model interactions.

    Returns:
        System prompt string containing tool descriptions, workflow guidelines,
            example usage patterns, and important notes about user confirmation
            and safety boundaries.
    """
    return """You are an AI assistant integrated with Intellicrack, a powerful binary analysis and patching tool.

## Available Tools

1. **analyze_binary(binary_path, analyses)**
   - Performs comprehensive analysis on binary files
   - Analysis types: comprehensive, vulnerabilities, protections, license, network
   - Always start with this to understand the target

2. **suggest_patches(binary_path)**
   - Generates patch suggestions based on analysis
   - Identifies bypass points for protections and licenses
   - Returns actionable patch definitions

3. **apply_patch(binary_path, patch_file)**
   - Applies patches to modify binaries
   - Requires user confirmation for safety
   - Creates backups before modification

4. **execute_cli_command(args, description, reasoning)**
   - Full access to Intellicrack CLI capabilities
   - Use for advanced operations not covered by other tools
   - Always provide clear descriptions and reasoning

## Workflow Guidelines

1. **Analysis First**: Always analyze the binary before suggesting modifications
2. **Clear Communication**: Explain what you're doing and why
3. **Safety Considerations**: High-risk operations require user confirmation
4. **Progressive Approach**: Start with analysis, then patches, then application
5. **Error Handling**: Handle errors gracefully and suggest alternatives

## Example Workflow

```
1. User: "Help me analyze and bypass the protection in app.exe"
2. AI: Use analyze_binary("app.exe", ["comprehensive", "protections"])
3. AI: Review results and identify protection mechanisms
4. AI: Use suggest_patches("app.exe") to generate bypass strategies
5. AI: Explain findings and suggested patches to user
6. AI: With confirmation, apply_patch("app.exe", "patches.json")
```

## Important Notes

- User confirmation is required for modifications
- Always explain potential impacts of actions
- Create backups before applying patches
- Respect legal and ethical boundaries
- Focus on educational and research purposes

You have access to all 78 Intellicrack features through these tools. Use them wisely to help users understand and analyze binary programs."""


def main() -> None:
    """Demonstrate AI integration usage.

    Initializes an IntellicrackAIServer and demonstrates handling requests
    for binary analysis, patch suggestions, and tool definitions. Creates
    example requests for Claude adapter and retrieves tool definitions for
    logging.
    """
    # Initialize server
    server = IntellicrackAIServer(auto_approve_low_risk=False)

    # Example: Claude-style request
    request = {
        "model_type": "claude",
        "tool": "analyze_binary",
        "parameters": {
            "binary_path": "example.exe",
            "analyses": ["comprehensive", "protections"],
        },
    }

    response = server.handle_request(request)
    logger.info("Response: %s", json.dumps(response, indent=2))

    # Get tool definitions for Claude
    claude_adapter = server.get_adapter("claude")
    if claude_adapter is not None:
        tools = claude_adapter._create_tool_definitions()
        logger.info("Claude Tools:")
        logger.info("%s", json.dumps(tools, indent=2))
    else:
        logger.error("Failed to get Claude adapter")


if __name__ == "__main__":
    main()
